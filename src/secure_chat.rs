//! Client-side Olm Triple-DH/Double Ratchet integration for NODO.
//!
//! This module deliberately keeps vodozemac's wire format and ratchet behavior
//! intact.  Application envelopes carry the vodozemac message type and bytes;
//! they do not add another message-encryption or nonce layer.  Private account
//! and session state is represented only by the internal `SecureAccount` value
//! and by encrypted state blobs intended for client-side storage.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    num::NonZeroU32,
};

use ring::{
    aead, digest, pbkdf2,
    rand::{SecureRandom, SystemRandom},
};
#[cfg(test)]
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use vodozemac::{
    base64_decode, base64_encode,
    olm::{
        Account, AccountPickle, DecryptionError, EncryptionError, OlmMessage, Session,
        SessionConfig, SessionCreationError, SessionPickle,
    },
    Curve25519PublicKey, Ed25519PublicKey, Ed25519Signature,
};
use zeroize::{Zeroize, Zeroizing};

const BUNDLE_DOMAIN: &[u8] = b"NODO/OLM/PREKEY/v1\0";
const DEVICE_IDENTITY_DOMAIN: &[u8] = b"NODO/OLM/DEVICE-IDENTITY/v1\0";
const STORAGE_VERSION: u8 = 1;
const STORAGE_KDF: &str = "PBKDF2-HMAC-SHA256";
const STORAGE_SALT_LENGTH: usize = 16;
const STORAGE_NONCE_LENGTH: usize = 12;
/// PBKDF2 work factor used for client-side state encryption.
///
/// This is intentionally stored in each blob so a future format can migrate
/// the work factor.  The current decoder accepts only this format version and
/// work factor.
pub const PBKDF2_ITERATIONS: u32 = 600_000;
const STORAGE_AAD: &[u8] = b"nodo-secure-chat-state-v1";

/// Errors returned by the public secure-chat API.
#[derive(Debug)]
pub enum CryptoError {
    /// A public key, signature, or message encoding was malformed.
    InvalidEncoding(String),
    /// A signed public bundle failed verification.
    InvalidBundleSignature,
    /// A supplied envelope did not match its authenticated protocol metadata.
    InvalidEnvelope(String),
    /// An outbound or inbound vodozemac session could not be created.
    SessionCreation(String),
    /// A vodozemac message could not be encrypted.
    Encryption(String),
    /// A vodozemac message failed authenticated decryption.
    Decryption(String),
    /// A requested session ID is not present in this account state.
    UnknownSession(String),
    /// An envelope attempted to use a session ID that is already present.
    SessionAlreadyExists(String),
    /// The serialized account/session state was not valid JSON or pickle data.
    Serialization(String),
    /// The storage password must not be empty.
    EmptyPassword,
    /// The encrypted state blob has an unsupported or malformed format.
    InvalidStorageBlob(String),
    /// The storage blob failed AES-GCM authentication.
    StorageAuthenticationFailed,
    /// The platform random source was unavailable.
    RandomnessUnavailable,
    /// A decrypted payload was not valid UTF-8.
    #[cfg(test)]
    InvalidUtf8,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidEncoding(message) => write!(f, "invalid encoding: {message}"),
            Self::InvalidBundleSignature => write!(f, "invalid public pre-key bundle signature"),
            Self::InvalidEnvelope(message) => write!(f, "invalid message envelope: {message}"),
            Self::SessionCreation(message) => write!(f, "session creation failed: {message}"),
            Self::Encryption(message) => write!(f, "message encryption failed: {message}"),
            Self::Decryption(message) => write!(f, "message decryption failed: {message}"),
            Self::UnknownSession(session_id) => write!(f, "unknown session: {session_id}"),
            Self::SessionAlreadyExists(session_id) => {
                write!(f, "session already exists: {session_id}")
            }
            Self::Serialization(message) => write!(f, "state serialization failed: {message}"),
            Self::EmptyPassword => write!(f, "storage password must not be empty"),
            Self::InvalidStorageBlob(message) => {
                write!(f, "invalid encrypted state blob: {message}")
            }
            Self::StorageAuthenticationFailed => {
                write!(f, "encrypted state authentication failed")
            }
            Self::RandomnessUnavailable => write!(f, "secure random source unavailable"),
            #[cfg(test)]
            Self::InvalidUtf8 => write!(f, "decrypted payload is not valid UTF-8"),
        }
    }
}

impl std::error::Error for CryptoError {}

/// A signed, public Olm pre-key bundle suitable for publication to a relay.
///
/// Only public keys and a signature are included.  The account and its private
/// one-time key material never appear in this type.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublicPreKeyBundle {
    /// The Ed25519 public key used to verify `signature`.
    pub ed25519_key: String,
    /// The account's long-term Curve25519 identity key.
    pub curve25519_key: String,
    /// A single-use Curve25519 pre-key.
    pub one_time_key: String,
    /// Ed25519 signature over the domain-separated identity/pre-key tuple.
    pub signature: String,
}

impl PublicPreKeyBundle {
    /// Verify the Ed25519 signature and key encodings in this bundle.
    pub fn verify(&self) -> Result<(), CryptoError> {
        let ed25519_key = Ed25519PublicKey::from_base64(&self.ed25519_key)
            .map_err(|error| CryptoError::InvalidEncoding(error.to_string()))?;
        let curve25519_key = parse_curve_key(&self.curve25519_key, "bundle identity key")?;
        let one_time_key = parse_curve_key(&self.one_time_key, "bundle one-time key")?;
        let signature = Ed25519Signature::from_base64(&self.signature)
            .map_err(|error| CryptoError::InvalidEncoding(error.to_string()))?;

        if ed25519_key
            .verify(
                &bundle_signature_message(&curve25519_key, &one_time_key),
                &signature,
            )
            .is_err()
        {
            return Err(CryptoError::InvalidBundleSignature);
        }

        Ok(())
    }
}

/// A device identity proof binding the Ed25519 signer to its Curve25519 key.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublicDeviceIdentity {
    pub ed25519_key: String,
    pub curve25519_key: String,
    pub signature: String,
}

impl PublicDeviceIdentity {
    /// Verify the device signature over the long-term Curve25519 identity key.
    pub fn verify(&self) -> Result<(), CryptoError> {
        let ed25519_key = Ed25519PublicKey::from_base64(&self.ed25519_key)
            .map_err(|error| CryptoError::InvalidEncoding(error.to_string()))?;
        let curve25519_key = parse_curve_key(&self.curve25519_key, "device identity key")?;
        let signature = Ed25519Signature::from_base64(&self.signature)
            .map_err(|error| CryptoError::InvalidEncoding(error.to_string()))?;
        ed25519_key
            .verify(&device_identity_message(&curve25519_key), &signature)
            .map_err(|_| CryptoError::InvalidBundleSignature)
    }
}

/// A JSON-serializable transport envelope around one vodozemac Olm message.
///
/// `type` is the vodozemac message type (`0` for pre-key, `1` for normal), and
/// `ciphertext` is the vodozemac message's base64 wire bytes.  No application
/// nonce or second encryption layer is added.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EncryptedEnvelope {
    /// The vodozemac session identifier.
    pub session_id: String,
    /// The vodozemac message type: `0` pre-key or `1` normal.
    #[serde(rename = "type")]
    pub message_type: u8,
    /// The sender's long-term Curve25519 identity key, base64 encoded.
    pub sender_curve_key: String,
    /// The vodozemac message bytes, base64 encoded.
    pub ciphertext: String,
}

/// The authenticated plaintext returned by [`SecureAccount::consume_message`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DecryptedMessage {
    /// The vodozemac session identifier used to decrypt this message.
    pub session_id: String,
    /// Plaintext bytes. JSON and UTF-8 text payloads can be decoded by callers.
    pub plaintext: Vec<u8>,
}

impl DecryptedMessage {
    /// Interpret the decrypted payload as UTF-8 text.
    #[cfg(test)]
    pub fn text(&self) -> Result<&str, CryptoError> {
        std::str::from_utf8(&self.plaintext).map_err(|_| CryptoError::InvalidUtf8)
    }

    /// Deserialize a plaintext payload as JSON in protocol tests.
    #[cfg(test)]
    pub fn json<T: DeserializeOwned>(&self) -> Result<T, CryptoError> {
        serde_json::from_slice(&self.plaintext)
            .map_err(|error| CryptoError::Serialization(error.to_string()))
    }
}

/// A JSON-serializable encrypted client-side state blob.
///
/// This is for IndexedDB or another client-side secret store, not for relay
/// submission.  It contains no account/session plaintext after encryption.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EncryptedStateBlob {
    /// Encrypted state format version.
    pub version: u8,
    /// KDF identifier.
    pub kdf: String,
    /// PBKDF2 work factor.
    pub iterations: u32,
    /// Random PBKDF2 salt, base64 encoded.
    pub salt: String,
    /// Fresh AES-GCM nonce, base64 encoded.
    pub nonce: String,
    /// AES-GCM ciphertext including its authentication tag, base64 encoded.
    pub ciphertext: String,
}

struct SessionState {
    session: Session,
    peer_curve_key: Curve25519PublicKey,
}

#[derive(Deserialize, Serialize)]
struct StoredSession {
    session_id: String,
    peer_curve_key: Curve25519PublicKey,
    session: SessionPickle,
}

#[derive(Deserialize, Serialize)]
struct AccountStatePickle {
    account: AccountPickle,
    sessions: Vec<StoredSession>,
}

/// A client-only Olm account and its active sessions.
///
/// This type intentionally does not implement `Serialize`, `Clone`, or
/// `Debug`, preventing accidental UI/relay serialization of private state.
/// Use [`SecureAccount::serialize_state`] and then encrypt the returned bytes
/// with [`encrypt_private_state`] before writing them to client storage.
pub struct SecureAccount {
    account: Account,
    sessions: BTreeMap<String, SessionState>,
}

impl SecureAccount {
    /// Create a new random account with no sessions.
    pub fn new() -> Self {
        Self {
            account: Account::new(),
            sessions: BTreeMap::new(),
        }
    }

    /// Return SHA-256 of the raw Ed25519 public identity key as a 0x-prefixed
    /// 32-byte value, matching the relay's wallet-binding challenge.
    pub fn identity_key_hash(&self) -> String {
        let hash = digest::digest(&digest::SHA256, self.account.ed25519_key().as_bytes());
        format!("0x{}", hex::encode(hash.as_ref()))
    }

    /// Sign this device's long-term Curve25519 identity key with its Ed25519
    /// identity key. The EIP-712 signature separately binds the Ed25519 key to
    /// the user's EVM wallet.
    pub fn public_device_identity(&self) -> PublicDeviceIdentity {
        let curve25519_key = self.account.curve25519_key();
        let signature = self.account.sign(&device_identity_message(&curve25519_key));
        PublicDeviceIdentity {
            ed25519_key: self.account.ed25519_key().to_base64(),
            curve25519_key: curve25519_key.to_base64(),
            signature: signature.to_base64(),
        }
    }

    /// Test helper that builds one public prekey bundle.
    #[cfg(test)]
    pub fn public_prekey_bundle(&mut self) -> Result<PublicPreKeyBundle, CryptoError> {
        self.public_prekey_bundles(1)?
            .into_iter()
            .next()
            .ok_or_else(|| CryptoError::InvalidEnvelope("no one-time prekey was generated".into()))
    }

    /// Test helper that generates a batch without a caller-supplied history.
    #[cfg(test)]
    pub fn public_prekey_bundles(
        &mut self,
        count: usize,
    ) -> Result<Vec<PublicPreKeyBundle>, CryptoError> {
        self.public_prekey_bundles_excluding(count, &BTreeSet::new())
    }

    /// Generate and sign a batch of single-use prekeys whose IDs have never
    /// been generated for this local profile. The caller persists the IDs
    /// before attempting relay registration so retries cannot republish them.
    pub fn public_prekey_bundles_excluding(
        &mut self,
        count: usize,
        known_ids: &BTreeSet<String>,
    ) -> Result<Vec<PublicPreKeyBundle>, CryptoError> {
        if count == 0 || count > 200 {
            return Err(CryptoError::InvalidEnvelope(
                "prekey batch size must be between 1 and 200".into(),
            ));
        }
        self.account.generate_one_time_keys(count);
        let mut keys = self
            .account
            .one_time_keys()
            .values()
            .copied()
            .filter(|key| !known_ids.contains(&one_time_key_id(key)))
            .collect::<Vec<_>>();
        if keys.len() < count {
            return Err(CryptoError::InvalidEnvelope(
                "account did not produce the requested one-time prekeys".into(),
            ));
        }
        keys.sort_by_key(one_time_key_id);
        keys.truncate(count);
        let curve25519_key = self.account.curve25519_key();
        let ed25519_key = self.account.ed25519_key().to_base64();
        let mut bundles = Vec::with_capacity(count);
        for one_time_key in keys {
            let signature = self
                .account
                .sign(&bundle_signature_message(&curve25519_key, &one_time_key));
            bundles.push(PublicPreKeyBundle {
                ed25519_key: ed25519_key.clone(),
                curve25519_key: curve25519_key.to_base64(),
                one_time_key: one_time_key.to_base64(),
                signature: signature.to_base64(),
            });
        }
        self.account.mark_keys_as_published();
        let unique = bundles
            .iter()
            .map(|bundle| bundle.one_time_key.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        if unique.len() != bundles.len() {
            return Err(CryptoError::InvalidEnvelope(
                "account generated a duplicate one-time prekey".into(),
            ));
        }
        Ok(bundles)
    }

    /// Create an outbound vodozemac session from a recipient Curve25519
    /// identity key and one-time key, both base64 encoded.
    ///
    /// The returned session ID is used with [`Self::encrypt_payload`].  When a
    /// signed bundle is available, prefer [`Self::create_outbound_session_from_bundle`].
    pub fn create_outbound_session(
        &mut self,
        recipient_curve_key: &str,
        recipient_one_time_key: &str,
    ) -> Result<String, CryptoError> {
        let recipient_curve_key = parse_curve_key(recipient_curve_key, "recipient identity key")?;
        let recipient_one_time_key =
            parse_curve_key(recipient_one_time_key, "recipient one-time key")?;
        let session = self
            .account
            .create_outbound_session(
                SessionConfig::version_1(),
                recipient_curve_key,
                recipient_one_time_key,
            )
            .map_err(session_creation_error)?;
        let session_id = session.session_id();
        if self.sessions.contains_key(&session_id) {
            return Err(CryptoError::SessionAlreadyExists(session_id));
        }
        self.sessions.insert(
            session_id.clone(),
            SessionState {
                session,
                peer_curve_key: recipient_curve_key,
            },
        );
        Ok(session_id)
    }

    /// Verify a signed recipient bundle and create an outbound session from it.
    pub fn create_outbound_session_from_bundle(
        &mut self,
        bundle: &PublicPreKeyBundle,
    ) -> Result<String, CryptoError> {
        bundle.verify()?;
        self.create_outbound_session(&bundle.curve25519_key, &bundle.one_time_key)
    }

    /// Encrypt a UTF-8/plaintext or already-serialized JSON payload.
    pub fn encrypt_payload(
        &mut self,
        session_id: &str,
        plaintext: impl AsRef<[u8]>,
    ) -> Result<EncryptedEnvelope, CryptoError> {
        let state = self
            .sessions
            .get_mut(session_id)
            .ok_or_else(|| CryptoError::UnknownSession(session_id.to_owned()))?;
        let message = state.session.encrypt(plaintext).map_err(encryption_error)?;
        let (message_type, ciphertext) = message.to_parts();
        let message_type = u8::try_from(message_type).map_err(|_| {
            CryptoError::InvalidEnvelope("unsupported vodozemac message type".into())
        })?;

        Ok(EncryptedEnvelope {
            session_id: session_id.to_owned(),
            message_type,
            sender_curve_key: self.account.curve25519_key().to_base64(),
            ciphertext: base64_encode(ciphertext),
        })
    }

    /// Serialize a JSON value and encrypt it using an existing session.
    pub fn encrypt_json<T: Serialize>(
        &mut self,
        session_id: &str,
        payload: &T,
    ) -> Result<EncryptedEnvelope, CryptoError> {
        let mut plaintext = serde_json::to_vec(payload)
            .map_err(|error| CryptoError::Serialization(error.to_string()))?;
        let encrypted = self.encrypt_payload(session_id, &plaintext);
        plaintext.zeroize();
        encrypted
    }

    /// Parse and consume an inbound pre-key or normal message.
    ///
    /// A pre-key message creates and stores the inbound session.  A normal
    /// message must reference an existing session.  In both cases the sender
    /// identity key in the envelope is checked against the session peer.
    pub fn consume_message(
        &mut self,
        envelope: &EncryptedEnvelope,
    ) -> Result<DecryptedMessage, CryptoError> {
        let ciphertext = base64_decode(&envelope.ciphertext)
            .map_err(|error| CryptoError::InvalidEncoding(error.to_string()))?;
        let message = OlmMessage::from_parts(envelope.message_type as usize, &ciphertext)
            .map_err(|error| CryptoError::InvalidEncoding(error.to_string()))?;
        let sender_curve_key = parse_curve_key(&envelope.sender_curve_key, "sender identity key")?;

        match message {
            OlmMessage::PreKey(prekey) => {
                if prekey.session_id() != envelope.session_id {
                    return Err(CryptoError::InvalidEnvelope(
                        "envelope session ID does not match pre-key message".into(),
                    ));
                }
                if sender_curve_key != prekey.identity_key() {
                    return Err(CryptoError::InvalidEnvelope(
                        "envelope sender key does not match pre-key message".into(),
                    ));
                }
                if self.sessions.contains_key(&envelope.session_id) {
                    return Err(CryptoError::SessionAlreadyExists(
                        envelope.session_id.clone(),
                    ));
                }

                let result = self
                    .account
                    .create_inbound_session(SessionConfig::version_1(), sender_curve_key, &prekey)
                    .map_err(session_creation_error)?;
                let session_id = result.session.session_id();
                if session_id != envelope.session_id {
                    return Err(CryptoError::InvalidEnvelope(
                        "inbound session ID does not match envelope".into(),
                    ));
                }
                let plaintext = result.plaintext;
                self.sessions.insert(
                    session_id.clone(),
                    SessionState {
                        session: result.session,
                        peer_curve_key: sender_curve_key,
                    },
                );
                Ok(DecryptedMessage {
                    session_id,
                    plaintext,
                })
            }
            OlmMessage::Normal(normal) => {
                let state = self
                    .sessions
                    .get_mut(&envelope.session_id)
                    .ok_or_else(|| CryptoError::UnknownSession(envelope.session_id.clone()))?;
                if state.peer_curve_key != sender_curve_key {
                    return Err(CryptoError::InvalidEnvelope(
                        "envelope sender key does not match session peer".into(),
                    ));
                }
                let message = OlmMessage::Normal(normal);
                let plaintext = state.session.decrypt(&message).map_err(decryption_error)?;
                Ok(DecryptedMessage {
                    session_id: envelope.session_id.clone(),
                    plaintext,
                })
            }
        }
    }

    /// Return the active session IDs without exposing session secrets.
    pub fn session_ids(&self) -> Vec<String> {
        self.sessions.keys().cloned().collect()
    }

    /// Serialize the account and all session pickle state for later local
    /// encryption.  The returned bytes are private state and must not be sent
    /// to the relay or written to plaintext localStorage.
    pub fn serialize_state(&self) -> Result<Vec<u8>, CryptoError> {
        let state = AccountStatePickle {
            account: self.account.pickle(),
            sessions: self
                .sessions
                .iter()
                .map(|(session_id, state)| StoredSession {
                    session_id: session_id.clone(),
                    peer_curve_key: state.peer_curve_key,
                    session: state.session.pickle(),
                })
                .collect(),
        };
        let mut serialized = Zeroizing::new(Vec::new());
        serde_json::to_writer(&mut *serialized, &state)
            .map_err(|error| CryptoError::Serialization(error.to_string()))?;
        Ok(std::mem::take(&mut *serialized))
    }

    /// Restore an account and sessions from bytes returned by
    /// [`Self::serialize_state`].
    pub fn deserialize_state(serialized: &[u8]) -> Result<Self, CryptoError> {
        let state: AccountStatePickle = serde_json::from_slice(serialized)
            .map_err(|error| CryptoError::Serialization(error.to_string()))?;
        let mut sessions = BTreeMap::new();
        for stored in state.sessions {
            let session = Session::from_pickle(stored.session);
            if session.session_id() != stored.session_id {
                return Err(CryptoError::Serialization(
                    "stored session ID does not match its pickle".into(),
                ));
            }
            if sessions
                .insert(
                    stored.session_id.clone(),
                    SessionState {
                        session,
                        peer_curve_key: stored.peer_curve_key,
                    },
                )
                .is_some()
            {
                return Err(CryptoError::Serialization(
                    "duplicate stored session ID".into(),
                ));
            }
        }
        Ok(Self {
            account: Account::from_pickle(state.account),
            sessions,
        })
    }
}

impl Default for SecureAccount {
    fn default() -> Self {
        Self::new()
    }
}

/// Initialize a new client account and its signed public one-time pre-key
/// bundle.
#[cfg(test)]
pub fn initialize_account() -> Result<(SecureAccount, PublicPreKeyBundle), CryptoError> {
    let mut account = SecureAccount::new();
    let bundle = account.public_prekey_bundle()?;
    Ok((account, bundle))
}

/// Encrypt already-serialized private account/session state for client-side
/// storage.  The returned blob is JSON-serializable but must not be submitted
/// to a server as a relay message.
pub fn encrypt_private_state(
    serialized_state: &[u8],
    password: &str,
) -> Result<EncryptedStateBlob, CryptoError> {
    if password.is_empty() {
        return Err(CryptoError::EmptyPassword);
    }

    let salt = random_array::<STORAGE_SALT_LENGTH>()?;
    let nonce = random_array::<STORAGE_NONCE_LENGTH>()?;
    let mut key_bytes = derive_storage_key(password.as_bytes(), &salt, PBKDF2_ITERATIONS)?;
    let unbound_key = aead::UnboundKey::new(&aead::AES_256_GCM, &key_bytes)
        .map_err(|_| CryptoError::InvalidStorageBlob("AES-256-GCM key rejected".into()))?;
    let key = aead::LessSafeKey::new(unbound_key);
    let nonce_for_key = aead::Nonce::assume_unique_for_key(nonce);
    let mut in_out = serialized_state.to_vec();
    if key
        .seal_in_place_append_tag(nonce_for_key, aead::Aad::from(STORAGE_AAD), &mut in_out)
        .is_err()
    {
        in_out.zeroize();
        key_bytes.zeroize();
        return Err(CryptoError::StorageAuthenticationFailed);
    }

    let blob = EncryptedStateBlob {
        version: STORAGE_VERSION,
        kdf: STORAGE_KDF.to_owned(),
        iterations: PBKDF2_ITERATIONS,
        salt: base64_encode(salt),
        nonce: base64_encode(nonce),
        ciphertext: base64_encode(&in_out),
    };
    in_out.zeroize();
    key_bytes.zeroize();
    Ok(blob)
}

/// Decrypt and authenticate a client-side state blob.
pub fn decrypt_private_state(
    blob: &EncryptedStateBlob,
    password: &str,
) -> Result<Vec<u8>, CryptoError> {
    if password.is_empty() {
        return Err(CryptoError::EmptyPassword);
    }
    if blob.version != STORAGE_VERSION {
        return Err(CryptoError::InvalidStorageBlob(
            "unsupported version".into(),
        ));
    }
    if blob.kdf != STORAGE_KDF || blob.iterations != PBKDF2_ITERATIONS {
        return Err(CryptoError::InvalidStorageBlob(
            "unsupported KDF parameters".into(),
        ));
    }

    let salt = decode_fixed::<STORAGE_SALT_LENGTH>(&blob.salt, "salt")?;
    let nonce = decode_fixed::<STORAGE_NONCE_LENGTH>(&blob.nonce, "nonce")?;
    let mut in_out = base64_decode(&blob.ciphertext)
        .map_err(|error| CryptoError::InvalidEncoding(error.to_string()))?;
    if in_out.len() < aead::AES_256_GCM.tag_len() {
        return Err(CryptoError::InvalidStorageBlob(
            "ciphertext is too short".into(),
        ));
    }

    let mut key_bytes = derive_storage_key(password.as_bytes(), &salt, blob.iterations)?;
    let unbound_key = aead::UnboundKey::new(&aead::AES_256_GCM, &key_bytes)
        .map_err(|_| CryptoError::InvalidStorageBlob("AES-256-GCM key rejected".into()))?;
    let key = aead::LessSafeKey::new(unbound_key);
    let result = key.open_in_place(
        aead::Nonce::assume_unique_for_key(nonce),
        aead::Aad::from(STORAGE_AAD),
        &mut in_out,
    );
    let plaintext = match result {
        Ok(plaintext) => plaintext.to_vec(),
        Err(_) => {
            in_out.zeroize();
            key_bytes.zeroize();
            return Err(CryptoError::StorageAuthenticationFailed);
        }
    };
    in_out.zeroize();
    key_bytes.zeroize();
    Ok(plaintext)
}

fn bundle_signature_message(
    curve25519_key: &Curve25519PublicKey,
    one_time_key: &Curve25519PublicKey,
) -> Vec<u8> {
    let mut message = Vec::with_capacity(BUNDLE_DOMAIN.len() + Curve25519PublicKey::LENGTH * 2);
    message.extend_from_slice(BUNDLE_DOMAIN);
    message.extend_from_slice(curve25519_key.as_bytes());
    message.extend_from_slice(one_time_key.as_bytes());
    message
}

fn device_identity_message(curve25519_key: &Curve25519PublicKey) -> Vec<u8> {
    let mut message =
        Vec::with_capacity(DEVICE_IDENTITY_DOMAIN.len() + Curve25519PublicKey::LENGTH);
    message.extend_from_slice(DEVICE_IDENTITY_DOMAIN);
    message.extend_from_slice(curve25519_key.as_bytes());
    message
}

fn one_time_key_id(key: &Curve25519PublicKey) -> String {
    let hash = digest::digest(&digest::SHA256, key.as_bytes());
    format!("otk-{}", hex::encode(hash.as_ref()))
}

fn parse_curve_key(value: &str, label: &str) -> Result<Curve25519PublicKey, CryptoError> {
    Curve25519PublicKey::from_base64(value)
        .map_err(|error| CryptoError::InvalidEncoding(format!("{label}: {error}")))
}

fn session_creation_error(error: SessionCreationError) -> CryptoError {
    CryptoError::SessionCreation(error.to_string())
}

fn encryption_error(error: EncryptionError) -> CryptoError {
    CryptoError::Encryption(error.to_string())
}

fn decryption_error(error: DecryptionError) -> CryptoError {
    CryptoError::Decryption(error.to_string())
}

fn random_array<const N: usize>() -> Result<[u8; N], CryptoError> {
    let mut bytes = [0u8; N];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| CryptoError::RandomnessUnavailable)?;
    Ok(bytes)
}

/// Generate a UUIDv4 using the operating-system or browser cryptographic RNG.
pub fn generate_uuid() -> Result<String, CryptoError> {
    let mut bytes = random_array::<16>()?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let encoded = hex::encode(bytes);
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &encoded[0..8],
        &encoded[8..12],
        &encoded[12..16],
        &encoded[16..20],
        &encoded[20..32]
    ))
}

fn derive_storage_key(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
) -> Result<[u8; 32], CryptoError> {
    let iterations = NonZeroU32::new(iterations).ok_or_else(|| {
        CryptoError::InvalidStorageBlob("PBKDF2 iterations must be non-zero".into())
    })?;
    let mut key = [0u8; 32];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        iterations,
        salt,
        password,
        &mut key,
    );
    Ok(key)
}

fn decode_fixed<const N: usize>(value: &str, label: &str) -> Result<[u8; N], CryptoError> {
    let decoded = base64_decode(value)
        .map_err(|error| CryptoError::InvalidEncoding(format!("{label}: {error}")))?;
    if decoded.len() != N {
        return Err(CryptoError::InvalidStorageBlob(format!(
            "{label} must be {N} bytes"
        )));
    }
    let mut result = [0u8; N];
    result.copy_from_slice(&decoded);
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn two_account_handshake_and_reply_round_trip() {
        let (mut alice, _alice_bundle) = initialize_account().expect("Alice account");
        let (mut bob, bob_bundle) = initialize_account().expect("Bob account");

        let session_id = alice
            .create_outbound_session_from_bundle(&bob_bundle)
            .expect("outbound session");
        let first = alice
            .encrypt_json(&session_id, &json!({ "text": "hello Bob" }))
            .expect("pre-key encryption");
        assert_eq!(first.message_type, 0);

        let received = bob.consume_message(&first).expect("inbound pre-key");
        assert_eq!(received.session_id, session_id);
        let value: serde_json::Value = received.json().expect("JSON plaintext");
        assert_eq!(value["text"], "hello Bob");

        let reply = bob
            .encrypt_payload(&session_id, "hello Alice")
            .expect("normal reply encryption");
        assert_eq!(reply.message_type, 1);
        let received_reply = alice.consume_message(&reply).expect("reply decryption");
        assert_eq!(received_reply.session_id, session_id);
        assert_eq!(received_reply.text().expect("UTF-8 reply"), "hello Alice");
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let (mut alice, _) = initialize_account().expect("Alice account");
        let (mut bob, bob_bundle) = initialize_account().expect("Bob account");
        let session_id = alice
            .create_outbound_session_from_bundle(&bob_bundle)
            .expect("outbound session");
        let original = alice
            .encrypt_payload(&session_id, "authenticated")
            .expect("encryption");
        let mut tampered = original.clone();
        let mut bytes = base64_decode(&tampered.ciphertext).expect("wire base64");
        let last = bytes.last_mut().expect("message MAC");
        *last ^= 1;
        tampered.ciphertext = base64_encode(bytes);
        assert!(bob.consume_message(&tampered).is_err());
        assert_eq!(
            bob.consume_message(&original)
                .expect("valid message")
                .text()
                .unwrap(),
            "authenticated"
        );
    }

    #[test]
    fn device_identity_and_prekey_batch_are_signed_and_unique() {
        let mut account = SecureAccount::new();
        let identity = account.public_device_identity();
        identity.verify().expect("device identity signature");
        assert_eq!(account.identity_key_hash().len(), 66);

        let bundles = account
            .public_prekey_bundles(20)
            .expect("generate prekey batch");
        assert_eq!(bundles.len(), 20);
        let unique = bundles
            .iter()
            .map(|bundle| bundle.one_time_key.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(unique.len(), 20);
        for bundle in &bundles {
            bundle.verify().expect("signed prekey bundle");
        }
    }

    #[test]
    fn storage_blob_rejects_wrong_password_and_tamper() {
        let (account, _) = initialize_account().expect("account");
        let state = account.serialize_state().expect("serialize");
        let blob = encrypt_private_state(&state, "correct horse battery staple").expect("encrypt");

        assert!(decrypt_private_state(&blob, "wrong password").is_err());
        let mut tampered = blob.clone();
        let mut ciphertext = base64_decode(&tampered.ciphertext).expect("ciphertext base64");
        ciphertext[0] ^= 1;
        tampered.ciphertext = base64_encode(ciphertext);
        assert!(decrypt_private_state(&tampered, "correct horse battery staple").is_err());
    }

    #[test]
    fn successive_prekey_batches_never_repeat_generated_ids() {
        let mut account = SecureAccount::new();
        let mut known_ids = BTreeSet::new();

        for _ in 0..3 {
            let bundles = account
                .public_prekey_bundles_excluding(20, &known_ids)
                .expect("generate new batch");
            assert_eq!(bundles.len(), 20);
            for bundle in bundles {
                let key = base64_decode(&bundle.one_time_key).expect("decode public key");
                let hash = digest::digest(&digest::SHA256, &key);
                let key_id = format!("otk-{}", hex::encode(hash.as_ref()));
                assert!(known_ids.insert(key_id), "prekey ID was repeated");
            }
        }

        assert_eq!(known_ids.len(), 60);
    }

    #[test]
    fn independent_initial_messages_use_distinct_prekey_sessions() {
        let mut alice = SecureAccount::new();
        let mut bob = SecureAccount::new();
        let bundles = bob.public_prekey_bundles(2).expect("two Bob bundles");
        let first_session = alice
            .create_outbound_session_from_bundle(&bundles[0])
            .expect("first outbound session");
        let second_session = alice
            .create_outbound_session_from_bundle(&bundles[1])
            .expect("second outbound session");
        assert_ne!(first_session, second_session);

        let first = alice
            .encrypt_payload(&first_session, "same plaintext")
            .expect("first initial message");
        let second = alice
            .encrypt_payload(&second_session, "same plaintext")
            .expect("second initial message");
        assert_eq!(first.message_type, 0);
        assert_eq!(second.message_type, 0);
        assert_ne!(first.ciphertext, second.ciphertext);
        assert_eq!(
            bob.consume_message(&first)
                .expect("first decrypt")
                .text()
                .unwrap(),
            "same plaintext"
        );
        assert_eq!(
            bob.consume_message(&second)
                .expect("second independent decrypt")
                .text()
                .unwrap(),
            "same plaintext"
        );
    }

    #[test]
    fn double_ratchet_decrypts_messages_delivered_out_of_order() {
        let (mut alice, _) = initialize_account().expect("Alice account");
        let (mut bob, bob_bundle) = initialize_account().expect("Bob account");
        let session_id = alice
            .create_outbound_session_from_bundle(&bob_bundle)
            .expect("outbound session");

        let initial = alice
            .encrypt_payload(&session_id, "initial")
            .expect("initial message");
        assert_eq!(
            bob.consume_message(&initial)
                .expect("initial decrypt")
                .text()
                .unwrap(),
            "initial"
        );
        let reply = bob
            .encrypt_payload(&session_id, "reply")
            .expect("ratchet reply");
        assert_eq!(
            alice
                .consume_message(&reply)
                .expect("reply decrypt")
                .text()
                .unwrap(),
            "reply"
        );

        let first = alice
            .encrypt_payload(&session_id, "second")
            .expect("second ratchet message");
        let second = alice
            .encrypt_payload(&session_id, "third")
            .expect("third ratchet message");
        assert_eq!(
            bob.consume_message(&second)
                .expect("out-of-order decrypt")
                .text()
                .unwrap(),
            "third"
        );
        assert_eq!(
            bob.consume_message(&first)
                .expect("delayed decrypt")
                .text()
                .unwrap(),
            "second"
        );
    }

    #[test]
    fn repeated_plaintext_uses_a_distinct_ratchet_ciphertext_each_time() {
        let (mut alice, _) = initialize_account().expect("Alice account");
        let (mut bob, bob_bundle) = initialize_account().expect("Bob account");
        let session_id = alice
            .create_outbound_session_from_bundle(&bob_bundle)
            .expect("outbound session");
        let initial = alice
            .encrypt_payload(&session_id, "handshake")
            .expect("initial message");
        bob.consume_message(&initial).expect("initial decrypt");
        let reply = bob
            .encrypt_payload(&session_id, "reply")
            .expect("ratchet reply");
        alice.consume_message(&reply).expect("reply decrypt");

        let first = alice
            .encrypt_payload(&session_id, "same payload")
            .expect("first normal message");
        let second = alice
            .encrypt_payload(&session_id, "same payload")
            .expect("second normal message");

        assert_eq!(first.message_type, 1);
        assert_eq!(second.message_type, 1);
        assert_ne!(first.ciphertext, second.ciphertext);
    }

    #[test]
    fn storage_nonce_is_fresh_for_each_encryption() {
        let first = encrypt_private_state(b"same state", "password").expect("first blob");
        let second = encrypt_private_state(b"same state", "password").expect("second blob");
        assert_ne!(first.nonce, second.nonce);
        assert_ne!(first.salt, second.salt);
        assert_ne!(first.ciphertext, second.ciphertext);
    }

    #[test]
    fn signed_bundle_rejects_key_substitution() {
        let (_, mut bundle) = initialize_account().expect("account");
        bundle.one_time_key = bundle.curve25519_key.clone();
        assert!(matches!(
            bundle.verify(),
            Err(CryptoError::InvalidBundleSignature)
        ));
    }

    #[test]
    fn serialized_session_state_restores_ratchet() {
        let (mut alice, _) = initialize_account().expect("Alice account");
        let (mut bob, bob_bundle) = initialize_account().expect("Bob account");
        let session_id = alice
            .create_outbound_session_from_bundle(&bob_bundle)
            .expect("session");
        let first = alice
            .encrypt_payload(&session_id, "stateful")
            .expect("message");
        bob.consume_message(&first).expect("first message");
        let serialized = alice.serialize_state().expect("serialize");
        let mut restored = SecureAccount::deserialize_state(&serialized).expect("restore");
        let reply = bob.encrypt_payload(&session_id, "reply").expect("reply");
        let received = restored
            .consume_message(&reply)
            .expect("restored decryption");
        assert_eq!(received.text().expect("UTF-8 reply"), "reply");
    }
}
