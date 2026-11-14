use std::{
    collections::{BTreeSet, HashMap},
    fmt,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

#[cfg(not(target_arch = "wasm32"))]
use std::time::{SystemTime, UNIX_EPOCH};

use ring::digest::{digest, SHA256};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha3::{Digest, Keccak256};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    relay_client,
    secure_chat::{
        decrypt_private_state, encrypt_private_state, generate_uuid, EncryptedEnvelope,
        EncryptedStateBlob, PublicDeviceIdentity, PublicPreKeyBundle, SecureAccount,
    },
    secure_storage,
    wallet_bridge::{self, IdentityKeyBinding},
};

const PROFILE_VERSION: u8 = 1;
const MAX_MESSAGES: usize = 500;
const MAX_REFRESH_BATCHES: usize = 10;
const PREKEY_BATCH_SIZE: usize = 20;
const PREKEY_LOW_WATERMARK: i64 = 8;
const IDENTITY_PREKEY_ID: &str = "nodo-curve-identity-v1";
const MAX_CHALLENGE_TTL_SECONDS: u64 = 5 * 60;
const MAX_BINDING_TTL_SECONDS: u64 = 365 * 24 * 60 * 60;
const AUTH_CLOCK_SKEW_SECONDS: u64 = 60;
const RELAY_ENVELOPE_TTL_SECONDS: i64 = 7 * 24 * 60 * 60;
const RELAY_EXPIRY_GRACE_SECONDS: i64 = 60;
const LOCAL_HISTORY_RETENTION_MS: i64 = 72 * 60 * 60 * 1000;
const MAX_CONVERSATION_WALLETS: usize = 200;
const MAX_RECEIVED_TOMBSTONES: usize = MAX_MESSAGES;
const SENDER_TIMESTAMP_FUTURE_GRACE_MS: i64 = 60 * 1000;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct LocalChatMessage {
    pub envelope_id: String,
    pub peer_wallet: String,
    pub peer_device_id: String,
    pub sender_wallet: String,
    pub sender_alias: String,
    pub body: String,
    pub created_at: i64,
    #[serde(default = "default_sender_timestamp_valid")]
    sender_timestamp_valid: bool,
    #[serde(default)]
    pub received_at: Option<i64>,
    #[serde(default)]
    local_ingested_at: Option<i64>,
    #[serde(default)]
    delivery_expires_at: Option<i64>,
    pub outgoing: bool,
    pub ciphertext_hash: String,
    pub status: String,
    pub anchor_tx: Option<String>,
    #[serde(default)]
    pub anchor_confirmed: bool,
    #[serde(default)]
    pub anchor_status: Option<String>,
    #[serde(default)]
    outbox_envelope: Option<String>,
    #[serde(default)]
    outbox_prekey_id: Option<String>,
}

impl LocalChatMessage {
    /// Return the authenticated sender timestamp only when it is usable for display.
    pub fn display_sent_at(&self) -> Option<i64> {
        (self.sender_timestamp_valid && self.created_at > 0).then_some(self.created_at)
    }

    /// Return a stable chronology key without presenting a local fallback as sender time.
    pub fn history_sort_timestamp(&self) -> i64 {
        self.display_sent_at()
            .or_else(|| {
                self.local_ingested_at
                    .or(self.received_at)
                    .filter(|timestamp| *timestamp > 0)
            })
            .unwrap_or(0)
    }
}

fn default_sender_timestamp_valid() -> bool {
    true
}

/// Metadata retained after an inbox envelope leaves visible history. It has
/// no plaintext, ciphertext, or routing fields; the hash binds duplicate ACKs
/// to the original outcome during the relay's bounded lifetime.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
struct ReceivedEnvelopeTombstone {
    envelope_id: String,
    ciphertext_hash: String,
    outcome: String,
    expires_at: i64,
    #[serde(default)]
    recorded_at: i64,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct LocalProfile {
    device_id: String,
    self_alias: String,
    sessions: HashMap<String, String>,
    trusted_fingerprints: HashMap<String, String>,
    #[serde(default)]
    generated_prekey_ids: BTreeSet<String>,
    #[serde(default)]
    unconfirmed_sessions: BTreeSet<String>,
    #[serde(default)]
    conversation_wallets: Vec<String>,
    #[serde(default)]
    received_envelope_tombstones: Vec<ReceivedEnvelopeTombstone>,
    messages: Vec<LocalChatMessage>,
}

impl LocalProfile {
    fn zeroize_sensitive(&mut self) {
        self.self_alias.zeroize();
        for state in self.sessions.values_mut() {
            state.zeroize();
        }
        self.sessions.clear();
        for message in &mut self.messages {
            message.sender_alias.zeroize();
            message.body.zeroize();
            message.outbox_envelope.zeroize();
            message.outbox_prekey_id.zeroize();
        }
        self.messages.clear();
        for tombstone in &mut self.received_envelope_tombstones {
            tombstone.ciphertext_hash.zeroize();
        }
        self.received_envelope_tombstones.clear();
    }
}

#[derive(Deserialize, Serialize)]
struct PersistedProfile {
    version: u8,
    device_id: String,
    self_alias: String,
    sessions: HashMap<String, String>,
    trusted_fingerprints: HashMap<String, String>,
    #[serde(default)]
    generated_prekey_ids: BTreeSet<String>,
    #[serde(default)]
    unconfirmed_sessions: BTreeSet<String>,
    #[serde(default)]
    conversation_wallets: Vec<String>,
    #[serde(default)]
    received_envelope_tombstones: Vec<ReceivedEnvelopeTombstone>,
    messages: Vec<LocalChatMessage>,
    account_state: Vec<u8>,
}

impl PersistedProfile {
    fn zeroize_sensitive(&mut self) {
        self.self_alias.zeroize();
        self.account_state.zeroize();
        for state in self.sessions.values_mut() {
            state.zeroize();
        }
        self.sessions.clear();
        for message in &mut self.messages {
            message.sender_alias.zeroize();
            message.body.zeroize();
            message.outbox_envelope.zeroize();
            message.outbox_prekey_id.zeroize();
        }
        self.messages.clear();
        for tombstone in &mut self.received_envelope_tombstones {
            tombstone.ciphertext_hash.zeroize();
        }
        self.received_envelope_tombstones.clear();
    }
}

struct LocalProfileSnapshot(Option<LocalProfile>);

impl LocalProfileSnapshot {
    fn new(profile: &LocalProfile) -> Self {
        Self(Some(profile.clone()))
    }

    fn take(&mut self) -> LocalProfile {
        self.0.take().expect("profile snapshot is available")
    }
}

impl Drop for LocalProfileSnapshot {
    fn drop(&mut self) {
        if let Some(profile) = self.0.as_mut() {
            profile.zeroize_sensitive();
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PeerTrust {
    FirstUse,
    Trusted,
    Changed,
}

#[derive(Clone, Debug)]
pub struct PeerDeviceInfo {
    pub wallet: String,
    pub device_id: String,
    pub identity_key_hash: String,
    pub fingerprint: String,
    pub trust: PeerTrust,
    pub available_prekeys: i64,
    pub online: Option<bool>,
}

#[derive(Clone, Debug)]
pub struct SendOutcome {
    pub status: String,
    pub warning: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct RefreshReport {
    pub delivered: usize,
    pub pending_senders: Vec<String>,
    pub rejected: usize,
    pub discarded_unverified: usize,
    pub malformed: usize,
    pub authentication_failed: usize,
    pub acknowledged: usize,
    pub more_pending: bool,
    #[serde(default)]
    pub metadata_capacity_full: bool,
}

#[derive(Clone)]
pub struct OperationGeneration(Arc<AtomicU64>);

impl OperationGeneration {
    pub fn new(initial: u64) -> Self {
        Self(Arc::new(AtomicU64::new(initial)))
    }

    pub fn load(&self, ordering: Ordering) -> u64 {
        self.0.load(ordering)
    }

    pub fn fetch_add(&self, value: u64, ordering: Ordering) -> u64 {
        self.0.fetch_add(value, ordering)
    }
}

impl PartialEq for OperationGeneration {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for OperationGeneration {}

impl fmt::Debug for OperationGeneration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OperationGeneration(<shared>)")
    }
}

#[derive(Clone)]
pub struct OperationGuard {
    generation: OperationGeneration,
    expected: u64,
}

impl OperationGuard {
    pub fn new(generation: OperationGeneration, expected: u64) -> Self {
        Self {
            generation,
            expected,
        }
    }

    fn ensure_current(&self) -> Result<(), String> {
        if self.generation.load(Ordering::SeqCst) == self.expected {
            Ok(())
        } else {
            Err("La wallet cambió o el perfil se bloqueó durante la operación.".into())
        }
    }
}

pub struct SecureMessagingSession {
    wallet: String,
    _profile_lock: secure_storage::WalletProfileLock,
    password: Zeroizing<String>,
    account: SecureAccount,
    profile: LocalProfile,
    access_token: Option<String>,
    operation_guard: OperationGuard,
    pub pending_senders: Vec<String>,
}

impl Drop for SecureMessagingSession {
    fn drop(&mut self) {
        self.access_token.zeroize();
        self.wallet.zeroize();
        self.pending_senders.zeroize();
        self.profile.zeroize_sensitive();
    }
}

#[derive(Debug, Deserialize)]
struct AuthChallenge {
    challenge_id: String,
    nonce: String,
    expires_at: u64,
    binding_expires_at: u64,
    typed_data: Value,
}

#[derive(Debug, Deserialize)]
struct AuthSession {
    access_token: String,
    wallet: String,
    device_id: String,
    expires_at: i64,
}

#[derive(Debug, Deserialize)]
struct DeviceBundles {
    wallet: String,
    devices: Vec<Value>,
}

#[derive(Clone, Debug, Deserialize)]
struct RemoteDevice {
    wallet: String,
    device_id: String,
    identity_key_hash: String,
    identity_key: String,
    binding_nonce: String,
    binding_expires_at: i64,
    binding_signature: String,
    signed_prekey: RemoteKey,
    available_one_time_prekeys: i64,
}

#[derive(Clone, Debug, Deserialize)]
struct RemoteKey {
    key_id: String,
    public_key: String,
    signature: String,
}

#[derive(Debug, Deserialize)]
struct ClaimedPrekey {
    wallet: String,
    device_id: String,
    key_id: String,
    public_key: String,
    signature: String,
}

#[derive(Debug, Deserialize)]
struct SendReceipt {
    envelope_id: String,
    expires_at: i64,
    #[serde(default)]
    recipient_online: bool,
}

#[derive(Debug, Deserialize)]
struct InboxEnvelope {
    envelope_id: String,
    sender_wallet: String,
    sender_device_id: String,
    prekey_id: Option<String>,
    ciphertext: String,
    created_at: i64,
    expires_at: i64,
}

#[derive(Debug, Deserialize)]
struct AckReceipt {
    acknowledged: u64,
}

#[derive(Serialize)]
struct DeliveryAcknowledgment {
    envelope_id: String,
    outcome: String,
    ciphertext_hash: String,
}

#[derive(Serialize)]
struct DeliveryStatusRequest {
    envelope_ids: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct DeliveryStatusRecord {
    envelope_id: String,
    status: String,
    delivered_at: Option<i64>,
    expires_at: i64,
    ciphertext_hash: Option<String>,
    recipient_online: bool,
}

#[derive(Debug, Deserialize)]
struct DeliveryStatusResponse {
    statuses: Vec<DeliveryStatusRecord>,
}

#[derive(Debug, Deserialize)]
struct PresenceReceipt {
    online: bool,
    expires_at: i64,
    checked_at: i64,
}

#[derive(Serialize)]
struct MessagePayload<'a> {
    version: u8,
    envelope_id: &'a str,
    sender_wallet: &'a str,
    sender_device_id: &'a str,
    recipient_wallet: &'a str,
    recipient_device_id: &'a str,
    sender_alias: &'a str,
    sent_at: i64,
    body: &'a str,
}

impl SecureMessagingSession {
    /// Unlock an existing encrypted profile or create a new wallet-local device.
    /// The passphrase and all Olm private state remain in this browser session.
    pub async fn unlock(
        wallet: &str,
        password: String,
        operation_guard: OperationGuard,
    ) -> Result<(Self, bool), String> {
        let password = Zeroizing::new(password);
        operation_guard.ensure_current()?;
        let wallet = normalize_wallet(wallet)?;
        let profile_lock = secure_storage::acquire_wallet_profile_lock(&wallet).await?;
        operation_guard.ensure_current()?;
        let saved = secure_storage::load_encrypted_state(&wallet).await?;
        operation_guard.ensure_current()?;
        let (account, profile, existed) = if let Some(serialized) = saved {
            let blob: EncryptedStateBlob = serde_json::from_str(&serialized)
                .map_err(|error| format!("El estado local cifrado no es válido: {error}"))?;
            let mut plaintext = decrypt_private_state(&blob, password.as_str())
                .map_err(|error| format!("No se pudo desbloquear el perfil: {error}"))?;
            let persisted = serde_json::from_slice::<PersistedProfile>(&plaintext);
            plaintext.zeroize();
            let mut persisted =
                persisted.map_err(|error| format!("El perfil cifrado no se pudo leer: {error}"))?;
            if persisted.version != PROFILE_VERSION {
                persisted.zeroize_sensitive();
                return Err(
                    "La versión del perfil E2EE no es compatible con esta aplicación.".into(),
                );
            }
            if persisted.device_id.is_empty() {
                persisted.zeroize_sensitive();
                return Err(
                    "El perfil local no contiene un identificador de dispositivo válido.".into(),
                );
            }
            let mut account_state = std::mem::take(&mut persisted.account_state);
            let restored = SecureAccount::deserialize_state(&account_state)
                .map_err(|error| format!("No se pudo restaurar el estado del ratchet: {error}"));
            account_state.zeroize();
            persisted.account_state.zeroize();
            let account = match restored {
                Ok(account) => account,
                Err(error) => {
                    persisted.zeroize_sensitive();
                    return Err(error);
                }
            };
            let profile = LocalProfile {
                device_id: std::mem::take(&mut persisted.device_id),
                self_alias: std::mem::take(&mut persisted.self_alias),
                sessions: std::mem::take(&mut persisted.sessions),
                trusted_fingerprints: std::mem::take(&mut persisted.trusted_fingerprints),
                generated_prekey_ids: std::mem::take(&mut persisted.generated_prekey_ids),
                unconfirmed_sessions: std::mem::take(&mut persisted.unconfirmed_sessions),
                conversation_wallets: std::mem::take(&mut persisted.conversation_wallets),
                received_envelope_tombstones: std::mem::take(
                    &mut persisted.received_envelope_tombstones,
                ),
                messages: std::mem::take(&mut persisted.messages),
            };
            (account, profile, true)
        } else {
            if password.chars().count() < 12 {
                return Err("Para crear un perfil nuevo, usa una contraseña local de al menos 12 caracteres.".into());
            }
            let profile = LocalProfile {
                device_id: generate_uuid().map_err(|error| error.to_string())?,
                ..LocalProfile::default()
            };
            (SecureAccount::new(), profile, false)
        };
        let mut session = Self {
            wallet,
            _profile_lock: profile_lock,
            password,
            account,
            profile,
            access_token: None,
            operation_guard,
            pending_senders: Vec::new(),
        };
        // Saving every unlock performs local retention cleanup and migrates
        // old profiles to the compact conversation/replay metadata fields.
        session.save().await?;
        session.ensure_operation_current()?;
        Ok((session, existed))
    }

    pub fn wallet(&self) -> &str {
        &self.wallet
    }

    pub fn device_id(&self) -> &str {
        &self.profile.device_id
    }

    pub fn self_alias(&self) -> &str {
        &self.profile.self_alias
    }

    pub fn messages(&self) -> &[LocalChatMessage] {
        &self.profile.messages
    }

    /// Return the peer wallets retained independently of message bodies.
    pub fn conversation_wallets(&self) -> Vec<String> {
        self.profile.conversation_wallets.clone()
    }

    /// Return a UI-safe message snapshot without exposing retry ciphertext.
    pub fn messages_for_display(&self) -> Vec<LocalChatMessage> {
        self.profile
            .messages
            .iter()
            .cloned()
            .map(|mut message| {
                message.outbox_envelope.zeroize();
                message.outbox_envelope = None;
                message.outbox_prekey_id.zeroize();
                message.outbox_prekey_id = None;
                message
            })
            .collect()
    }

    /// Prune local message bodies/retry ciphertext without requiring relay
    /// authentication. The return value is the number of visible messages
    /// removed (including the defensive MAX_MESSAGES cap).
    pub async fn prune_local_history(&mut self) -> Result<usize, String> {
        self.ensure_operation_current()?;
        let (removed, changed) = prune_local_profile(&mut self.profile, timestamp_ms());
        if changed {
            self.save().await?;
            self.ensure_operation_current()?;
        }
        Ok(removed)
    }

    pub fn has_session(&self) -> bool {
        self.access_token.is_some()
    }

    pub async fn renew_presence(&mut self) -> Result<(), String> {
        self.ensure_operation_current()?;
        let token = self.access_token.as_deref().ok_or_else(|| {
            "Registra el dispositivo en el relay antes de renovar presencia.".to_string()
        })?;
        let receipt: PresenceReceipt = relay_client::call(
            "/v1/presence/heartbeat",
            "POST",
            Some(json!({})),
            Some(token),
        )
        .await?;
        self.ensure_operation_current()?;
        if !receipt.online || receipt.expires_at <= receipt.checked_at {
            return Err("El relay no confirmó un lease de presencia activo.".into());
        }
        Ok(())
    }

    pub async fn mark_presence_offline(&mut self) -> Result<(), String> {
        let Some(token) = self.access_token.as_deref() else {
            return Ok(());
        };
        let receipt: PresenceReceipt =
            relay_client::call("/v1/presence/offline", "POST", Some(json!({})), Some(token))
                .await?;
        if receipt.online || receipt.expires_at != 0 {
            return Err("El relay no confirmó que el dispositivo quedó offline.".into());
        }
        Ok(())
    }

    fn ensure_operation_current(&self) -> Result<(), String> {
        self.operation_guard.ensure_current()
    }

    /// Explicit user-triggered EIP-712 wallet authentication and public key
    /// registration. No transaction or gas payment is requested for this step.
    pub async fn authenticate_and_register(&mut self) -> Result<(), String> {
        self.ensure_operation_current()?;
        let identity_key_hash = self.account.identity_key_hash();
        let challenge: AuthChallenge = relay_client::call(
            "/v1/auth/challenge",
            "POST",
            Some(json!({
                "wallet": self.wallet,
                "device_id": self.profile.device_id,
                "identity_key_hash": identity_key_hash,
            })),
            None,
        )
        .await?;
        self.ensure_operation_current()?;
        verify_challenge_shape(
            &challenge,
            &self.wallet,
            &self.profile.device_id,
            &identity_key_hash,
        )?;
        let binding = IdentityKeyBinding {
            wallet: self.wallet.clone(),
            device_id: self.profile.device_id.clone(),
            identity_key_hash: identity_key_hash.clone(),
            nonce: challenge.nonce.clone(),
            expires_at: challenge.binding_expires_at,
        };
        let signature = wallet_bridge::sign_identity_key_binding(&binding).await?;
        self.ensure_operation_current()?;
        let signer =
            wallet_bridge::recover_identity_key_binding_signer(&binding, &signature).await?;
        self.ensure_operation_current()?;
        if !signer.eq_ignore_ascii_case(&self.wallet) {
            return Err(
                "La firma de MetaMask no corresponde a esta wallet; no se registró el dispositivo."
                    .into(),
            );
        }
        let mut auth: AuthSession = relay_client::call(
            "/v1/auth/verify",
            "POST",
            Some(json!({
                "challenge_id": challenge.challenge_id,
                "wallet": self.wallet,
                "device_id": self.profile.device_id,
                "identity_key_hash": identity_key_hash,
                "nonce": challenge.nonce,
                "expires_at": challenge.expires_at,
                "binding_expires_at": challenge.binding_expires_at,
                "signature": signature,
            })),
            None,
        )
        .await?;
        self.ensure_operation_current()?;
        if !auth.wallet.eq_ignore_ascii_case(&self.wallet)
            || auth.device_id != self.profile.device_id
            || auth.access_token.is_empty()
            || auth.expires_at <= 0
        {
            auth.access_token.zeroize();
            return Err("El relay devolvió una sesión de wallet incompleta o incompatible.".into());
        }
        let token = Zeroizing::new(std::mem::take(&mut auth.access_token));

        let own_bundles = self.fetch_remote_devices(&self.wallet).await?;
        self.ensure_operation_current()?;
        let existing = own_bundles
            .iter()
            .find(|(device, _)| device.device_id == self.profile.device_id);
        if let Some((device, _)) = existing {
            if !device
                .identity_key_hash
                .eq_ignore_ascii_case(&identity_key_hash)
            {
                return Err("La clave de identidad registrada no coincide con este perfil local. No se reemplazó automáticamente; usa un dispositivo nuevo.".into());
            }
        }
        let available = existing
            .map(|(device, _)| device.available_one_time_prekeys)
            .unwrap_or(0);
        let count = if existing.is_none() || available < PREKEY_LOW_WATERMARK {
            PREKEY_BATCH_SIZE.saturating_sub(usize::try_from(available.max(0)).unwrap_or(0))
        } else {
            0
        };
        let device_identity = self.account.public_device_identity();
        device_identity.verify().map_err(|error| {
            format!("La prueba interna de identidad del dispositivo falló: {error}")
        })?;
        let public_identity_key = relay_client::standard_to_urlsafe(&device_identity.ed25519_key)?;
        let curve_identity_key =
            relay_client::standard_to_urlsafe(&device_identity.curve25519_key)?;
        let curve_identity_signature =
            relay_client::standard_to_urlsafe(&device_identity.signature)?;
        let bundles = if count == 0 {
            Vec::new()
        } else {
            self.account
                .public_prekey_bundles_excluding(count, &self.profile.generated_prekey_ids)
                .map_err(|error| {
                    format!("No se pudieron generar prekeys independientes: {error}")
                })?
        };
        let mut generated_prekey_ids = Vec::with_capacity(count);
        let one_time_prekeys = bundles
            .into_iter()
            .map(|bundle| {
                let public_key = relay_client::standard_to_urlsafe(&bundle.one_time_key)?;
                let signature = relay_client::standard_to_urlsafe(&bundle.signature)?;
                let decoded = relay_client::decode_urlsafe(&public_key)?;
                let key_id = format!("otk-{}", hex::encode(digest(&SHA256, &decoded).as_ref()));
                generated_prekey_ids.push(key_id.clone());
                Ok(json!({ "key_id": key_id, "public_key": public_key, "signature": signature }))
            })
            .collect::<Result<Vec<_>, String>>()?;
        if !generated_prekey_ids.is_empty() {
            self.profile
                .generated_prekey_ids
                .extend(generated_prekey_ids);
            self.save().await?;
        }
        self.ensure_operation_current()?;
        let _: Value = relay_client::call(
            "/v1/devices",
            "POST",
            Some(json!({
                "device_id": self.profile.device_id,
                "identity_key_hash": identity_key_hash,
                "identity_key": public_identity_key,
                "binding_nonce": challenge.nonce,
                "binding_expires_at": challenge.binding_expires_at,
                "binding_signature": signature,
                "signed_prekey": {
                    "key_id": IDENTITY_PREKEY_ID,
                    "public_key": curve_identity_key,
                    "signature": curve_identity_signature,
                },
                "one_time_prekeys": one_time_prekeys,
            })),
            Some(token.as_str()),
        )
        .await?;
        self.ensure_operation_current()?;
        self.save().await?;
        self.ensure_operation_current()?;
        self.access_token = Some(token.to_string());
        Ok(())
    }

    /// Fetch and cryptographically validate all public device bundles for a
    /// wallet, returning a safety fingerprint and the local trust state.
    pub async fn inspect_peer(&self, wallet: &str) -> Result<Vec<PeerDeviceInfo>, String> {
        self.fetch_remote_devices(wallet)
            .await
            .map(|devices| devices.into_iter().map(|(_, info)| info).collect())
    }

    /// Explicitly accept a key after the user compares its fingerprint over a
    /// separate channel. Changed keys are never accepted automatically.
    pub async fn trust_peer(
        &mut self,
        wallet: &str,
        device_id: &str,
        expected_hash: &str,
    ) -> Result<(), String> {
        self.ensure_operation_current()?;
        let wallet = normalize_wallet(wallet)?;
        let devices = self.fetch_remote_devices(&wallet).await?;
        self.ensure_operation_current()?;
        let (_, info) = devices
            .into_iter()
            .find(|(device, _)| device.device_id == device_id)
            .ok_or_else(|| "El dispositivo ya no está publicado para esa wallet.".to_string())?;
        if !info.identity_key_hash.eq_ignore_ascii_case(expected_hash) {
            return Err(
                "La huella cambió mientras revisabas el contacto. Vuelve a inspeccionar la wallet."
                    .into(),
            );
        }
        self.profile
            .trusted_fingerprints
            .insert(peer_key(&wallet, device_id), info.identity_key_hash);
        self.save().await
    }

    pub async fn set_self_alias(&mut self, alias: &str) -> Result<(), String> {
        self.ensure_operation_current()?;
        let alias = alias.trim();
        if alias.chars().count() > 48 {
            return Err("El alias debe tener como máximo 48 caracteres.".into());
        }
        self.profile.self_alias = alias.to_string();
        self.save().await
    }

    pub async fn send_message(
        &mut self,
        recipient_wallet: &str,
        recipient_device_id: &str,
        body: &str,
    ) -> Result<SendOutcome, String> {
        self.send_message_inner(recipient_wallet, recipient_device_id, body, true)
            .await
    }

    async fn send_message_inner(
        &mut self,
        recipient_wallet: &str,
        recipient_device_id: &str,
        body: &str,
        retry_expired_reservation: bool,
    ) -> Result<SendOutcome, String> {
        self.ensure_operation_current()?;
        let recipient_wallet = normalize_wallet(recipient_wallet)?;
        if recipient_wallet.eq_ignore_ascii_case(&self.wallet) {
            return Err(
                "Elige otra wallet; no puedes enviarte un mensaje a tu propia dirección.".into(),
            );
        }
        remember_conversation_wallet(&mut self.profile, &recipient_wallet);
        let body = body.trim();
        if body.is_empty() || body.chars().count() > 4096 {
            return Err("El mensaje debe contener entre 1 y 4096 caracteres.".into());
        }
        let token = self.access_token.as_deref().ok_or_else(|| {
            "Primero registra este dispositivo con una firma EIP-712 de MetaMask.".to_string()
        })?;
        let devices = self.fetch_remote_devices(&recipient_wallet).await?;
        self.ensure_operation_current()?;
        let (recipient, info) = devices
            .into_iter()
            .find(|(device, _)| device.device_id == recipient_device_id)
            .ok_or_else(|| {
                "No se encontró ese dispositivo registrado de la wallet destinataria.".to_string()
            })?;
        if info.trust != PeerTrust::Trusted {
            return Err(
                "Verifica y confirma la huella de seguridad del destinatario antes de enviar."
                    .into(),
            );
        }
        let envelope_id = generate_uuid().map_err(|error| error.to_string())?;
        let sent_at = timestamp_ms();
        let payload = MessagePayload {
            version: 1,
            envelope_id: &envelope_id,
            sender_wallet: &self.wallet,
            sender_device_id: &self.profile.device_id,
            recipient_wallet: &recipient_wallet,
            recipient_device_id,
            sender_alias: &self.profile.self_alias,
            sent_at,
            body,
        };
        let session_key = peer_key(&recipient_wallet, recipient_device_id);
        let existing_session = self
            .profile
            .sessions
            .get(&session_key)
            .filter(|session_id| !self.profile.unconfirmed_sessions.contains(*session_id))
            .cloned();
        if existing_session.is_none() && recipient.available_one_time_prekeys <= 0 {
            return Err("El destinatario no tiene prekeys de un solo uso disponibles. Pídele que abra NODO, desbloquee y registre su dispositivo.".into());
        }
        let mut prekey_id = None;
        let session_id = if let Some(session_id) = existing_session {
            if !self
                .account
                .session_ids()
                .iter()
                .any(|item| item == &session_id)
            {
                return Err("El perfil perdió el estado local de esta conversación. No se intentará enviar un mensaje incompatible.".into());
            }
            session_id
        } else {
            let claim: ClaimedPrekey = relay_client::call(
                &format!(
                    "/v1/bundles/{}/{}/one-time-prekeys/claim",
                    recipient_wallet, recipient_device_id
                ),
                "POST",
                Some(json!({ "envelope_id": envelope_id.clone() })),
                Some(token),
            )
            .await?;
            self.ensure_operation_current()?;
            if !claim.wallet.eq_ignore_ascii_case(&recipient_wallet)
                || claim.device_id != recipient_device_id
            {
                return Err(
                    "El relay devolvió una prekey para una wallet/dispositivo distinto.".into(),
                );
            }
            let bundle = PublicPreKeyBundle {
                ed25519_key: relay_client::urlsafe_to_standard(&recipient.identity_key)?,
                curve25519_key: relay_client::urlsafe_to_standard(
                    &recipient.signed_prekey.public_key,
                )?,
                one_time_key: relay_client::urlsafe_to_standard(&claim.public_key)?,
                signature: relay_client::urlsafe_to_standard(&claim.signature)?,
            };
            bundle.verify().map_err(|error| {
                format!("La firma de la prekey del destinatario no es válida: {error}")
            })?;
            let session_id = self
                .account
                .create_outbound_session_from_bundle(&bundle)
                .map_err(|error| {
                    format!("No se pudo iniciar la sesión Olm del destinatario: {error}")
                })?;
            self.profile
                .sessions
                .insert(session_key, session_id.clone());
            self.profile.unconfirmed_sessions.insert(session_id.clone());
            prekey_id = Some(claim.key_id);
            session_id
        };
        let envelope = self
            .account
            .encrypt_json(&session_id, &payload)
            .map_err(|error| format!("No se pudo cifrar el mensaje con el ratchet: {error}"))?;
        let mut envelope_bytes = serde_json::to_vec(&envelope)
            .map_err(|error| format!("No se pudo codificar el sobre cifrado: {error}"))?;
        let ciphertext_hash = keccak_hex(&envelope_bytes);
        let encoded_envelope = relay_client::encode_urlsafe(&envelope_bytes);
        envelope_bytes.zeroize();

        let message = LocalChatMessage {
            envelope_id: envelope_id.clone(),
            peer_wallet: recipient_wallet.clone(),
            peer_device_id: recipient_device_id.to_string(),
            sender_wallet: self.wallet.clone(),
            sender_alias: self.profile.self_alias.clone(),
            body: body.to_string(),
            created_at: sent_at,
            sender_timestamp_valid: true,
            received_at: None,
            local_ingested_at: None,
            delivery_expires_at: None,
            outgoing: true,
            ciphertext_hash,
            status: "queued".to_string(),
            anchor_tx: None,
            anchor_confirmed: false,
            anchor_status: None,
            outbox_envelope: Some(encoded_envelope),
            outbox_prekey_id: prekey_id,
        };
        let is_initial_prekey_message = message.outbox_prekey_id.is_some();
        self.profile.messages.insert(0, message);
        let _ = prune_local_profile(&mut self.profile, sent_at);
        self.save().await?;
        self.ensure_operation_current()?;

        match self.transmit_outbox(&envelope_id).await {
            Ok(()) => Ok(SendOutcome {
                status: self
                    .profile
                    .messages
                    .iter()
                    .find(|message| message.envelope_id == envelope_id)
                    .map(|message| message.status.clone())
                    .unwrap_or_else(|| "queued".to_string()),
                warning: None,
            }),
            Err(error) if is_relay_integrity_error(&error) => {
                self.mark_outbox_terminal(&envelope_id, "integrity_error", error)
                    .await
            }
            Err(error) if is_expired_relay_envelope(&error) => {
                self.mark_outbox_terminal(&envelope_id, "expired", error)
                    .await
            }
            Err(error) if is_permanent_relay_error(&error) => {
                self.mark_outbox_terminal(&envelope_id, "relay_rejected", error)
                    .await
            }
            Err(error)
                if retry_expired_reservation
                    && is_initial_prekey_message
                    && is_expired_prekey_reservation(&error) =>
            {
                let retry = Box::pin(self.retry_outbox(&envelope_id)).await?;
                self.ensure_operation_current()?;
                let status = retry.status;
                let detail = retry
                    .warning
                    .unwrap_or_else(|| "el relay aceptó el nuevo sobre cifrado".to_string());
                Ok(SendOutcome {
                    status,
                    warning: Some(format!(
                        "La reserva de prekey expiró; NODO la renovó automáticamente con una sesión y OTK nuevas. {detail}"
                    )),
                })
            }
            Err(error) => {
                let status = self
                    .profile
                    .messages
                    .iter()
                    .find(|message| message.envelope_id == envelope_id)
                    .map(|message| message.status.clone())
                    .unwrap_or_else(|| "queued".to_string());
                Ok(SendOutcome {
                    status,
                    warning: Some(format!(
                        "El estado E2EE quedó guardado localmente, pero el relay aún no confirmó la entrega o el último guardado falló: {error}"
                    )),
                })
            }
        }
    }

    pub async fn retry_outbox(&mut self, envelope_id: &str) -> Result<SendOutcome, String> {
        self.ensure_operation_current()?;
        let (needs_new_session, recipient_wallet, recipient_device_id, body, expired) = {
            let message = self
                .profile
                .messages
                .iter()
                .find(|message| message.envelope_id == envelope_id)
                .ok_or_else(|| {
                    "No se encontró el mensaje pendiente en la cola local.".to_string()
                })?;
            if message.outbox_envelope.is_none() {
                return Err("Este mensaje no tiene una copia pendiente para reintentar.".into());
            }
            (
                message.outbox_prekey_id.is_some(),
                message.peer_wallet.clone(),
                message.peer_device_id.clone(),
                Zeroizing::new(message.body.clone()),
                relay_envelope_expired(
                    message.delivery_expires_at,
                    message.created_at,
                    timestamp_ms() / 1000,
                    true,
                ),
            )
        };
        if expired {
            let message = self
                .profile
                .messages
                .iter_mut()
                .find(|message| message.envelope_id == envelope_id)
                .ok_or_else(|| {
                    "No se encontró el mensaje pendiente en la cola local.".to_string()
                })?;
            message.status = "expired".to_string();
            message.outbox_envelope = None;
            message.outbox_prekey_id = None;
            self.save().await?;
            self.ensure_operation_current()?;
            return Ok(SendOutcome {
                status: "expired".to_string(),
                warning: None,
            });
        }
        match self.transmit_outbox(envelope_id).await {
            Ok(()) => Ok(SendOutcome {
                status: self
                    .profile
                    .messages
                    .iter()
                    .find(|message| message.envelope_id == envelope_id)
                    .map(|message| message.status.clone())
                    .unwrap_or_else(|| "queued".to_string()),
                warning: None,
            }),
            Err(error) if needs_new_session && is_expired_prekey_reservation(&error) => {
                self.ensure_operation_current()?;
                let new_message = self
                    .send_message_inner(
                        &recipient_wallet,
                        &recipient_device_id,
                        body.as_str(),
                        false,
                    )
                    .await?;
                self.ensure_operation_current()?;
                if let Some(message) = self
                    .profile
                    .messages
                    .iter_mut()
                    .find(|message| message.envelope_id == envelope_id)
                {
                    message.status = "replaced".to_string();
                    message.outbox_envelope = None;
                    message.outbox_prekey_id = None;
                }
                self.save().await?;
                self.ensure_operation_current()?;
                let summary = if let Some(warning) = new_message.warning {
                    format!("La reserva anterior expiró; se creó un nuevo sobre cifrado. {warning}")
                } else if new_message.status == "sent" {
                    "La reserva anterior expiró; el mensaje se volvió a cifrar y el relay aceptó el nuevo sobre.".to_string()
                } else {
                    "La reserva anterior expiró; el mensaje se volvió a cifrar y quedó en la cola local para reintentar.".to_string()
                };
                Ok(SendOutcome {
                    status: new_message.status,
                    warning: Some(summary),
                })
            }
            Err(error) if is_relay_integrity_error(&error) => {
                self.mark_outbox_terminal(envelope_id, "integrity_error", error)
                    .await
            }
            Err(error) if is_expired_relay_envelope(&error) => {
                self.mark_outbox_terminal(envelope_id, "expired", error)
                    .await
            }
            Err(error) if is_permanent_relay_error(&error) => {
                self.mark_outbox_terminal(envelope_id, "relay_rejected", error)
                    .await
            }
            Err(error) => Err(error),
        }
    }

    async fn mark_outbox_terminal(
        &mut self,
        envelope_id: &str,
        status: &str,
        detail: String,
    ) -> Result<SendOutcome, String> {
        self.ensure_operation_current()?;
        let message = self
            .profile
            .messages
            .iter_mut()
            .find(|message| message.envelope_id == envelope_id)
            .ok_or_else(|| "No se encontró el mensaje pendiente.".to_string())?;
        message.status = status.to_string();
        message.outbox_envelope = None;
        message.outbox_prekey_id = None;
        self.save().await?;
        self.ensure_operation_current()?;
        Ok(SendOutcome {
            status: status.to_string(),
            warning: Some(detail),
        })
    }

    async fn transmit_outbox(&mut self, envelope_id: &str) -> Result<(), String> {
        self.ensure_operation_current()?;
        let token = self.access_token.as_deref().ok_or_else(|| {
            "La sesión del relay expiró. Vuelve a firmar el acceso para reintentar.".to_string()
        })?;
        let message = self
            .profile
            .messages
            .iter()
            .find(|message| message.envelope_id == envelope_id)
            .ok_or_else(|| "No se encontró el mensaje pendiente.".to_string())?;
        let encoded = message
            .outbox_envelope
            .as_deref()
            .ok_or_else(|| "El sobre cifrado pendiente no está disponible.".to_string())?;
        let ciphertext = Zeroizing::new(relay_client::decode_urlsafe(encoded)?);
        let body = json!({
            "recipient_wallet": message.peer_wallet,
            "recipient_device_id": message.peer_device_id,
            "envelope_id": message.envelope_id,
            "ciphertext": relay_client::encode_urlsafe(&ciphertext),
            "prekey_id": message.outbox_prekey_id,
        });
        let result: Result<SendReceipt, String> =
            relay_client::call("/v1/messages", "POST", Some(body), Some(token)).await;
        self.ensure_operation_current()?;
        let (recipient_online, expires_at) = match result {
            Ok(receipt) if receipt.envelope_id == envelope_id && receipt.expires_at > 0 => {
                (receipt.recipient_online, receipt.expires_at)
            }
            Ok(_) => {
                return Err("relay-integrity-error: el relay devolvió un recibo distinto del mensaje enviado.".into());
            }
            Err(error) => return Err(error),
        };
        if let Some(message) = self
            .profile
            .messages
            .iter_mut()
            .find(|message| message.envelope_id == envelope_id)
        {
            message.delivery_expires_at = Some(expires_at);
            message.status = if recipient_online {
                "awaiting_delivery".to_string()
            } else {
                "waiting_online".to_string()
            };
        }
        self.save().await?;
        self.ensure_operation_current()
    }

    /// Retrieve and authenticate ciphertext envelopes; acceptance and rejection
    /// ACKs are bound to the exact ciphertext hash before the relay can purge it.
    pub async fn refresh_inbox(&mut self) -> Result<RefreshReport, String> {
        self.ensure_operation_current()?;
        if self.access_token.is_none() {
            return Err("Registra este dispositivo para recibir mensajes cifrados.".to_string());
        }
        self.prune_local_history().await?;
        self.renew_presence().await?;
        self.ensure_operation_current()?;
        let mut report = RefreshReport::default();
        let mut keep_scanning = true;
        for batch_index in 0..MAX_REFRESH_BATCHES {
            if !keep_scanning {
                break;
            }
            let envelopes: Vec<InboxEnvelope> = relay_client::call(
                "/v1/inbox?limit=50",
                "GET",
                None,
                self.access_token.as_deref(),
            )
            .await?;
            self.ensure_operation_current()?;
            let batch_len = envelopes.len();
            if batch_len == 0 {
                break;
            }

            let mut acknowledgements: Vec<DeliveryAcknowledgment> = Vec::new();
            let mut changed = false;
            let mut blocked_by_lookup_failure = false;
            let mut peer_cache: HashMap<String, Vec<(RemoteDevice, PeerDeviceInfo)>> =
                HashMap::new();
            let mut profile_before_batch = LocalProfileSnapshot::new(&self.profile);
            let account_before_batch =
                Zeroizing::new(self.account.serialize_state().map_err(|error| {
                    format!("No se pudo guardar el punto de restauración del inbox: {error}")
                })?);

            for remote_envelope in envelopes {
                let received_at = timestamp_ms();
                let envelope_bytes = match relay_client::decode_urlsafe(&remote_envelope.ciphertext)
                {
                    Ok(bytes) => bytes,
                    Err(_) => {
                        report.rejected += 1;
                        report.malformed += 1;
                        // Without the original bytes, no exact ciphertext hash
                        // can be computed. Do not ACK and risk purging a
                        // different relay value; the relay will expire it.
                        continue;
                    }
                };
                let envelope_hash = keccak_hex(&envelope_bytes);
                changed |= prune_received_tombstones(&mut self.profile, received_at);
                if let Some(tombstone) = self
                    .profile
                    .received_envelope_tombstones
                    .iter()
                    .find(|item| item.envelope_id == remote_envelope.envelope_id)
                {
                    let outcome = tombstone_ack_outcome(tombstone, &envelope_hash);
                    acknowledgements.push(delivery_ack(
                        remote_envelope.envelope_id.clone(),
                        outcome,
                        envelope_hash,
                    ));
                    continue;
                }
                if !reserve_tombstone_capacity(&mut self.profile, received_at) {
                    // Exact metadata is fail-closed: never decrypt or advance
                    // the ratchet for a new ID that cannot be remembered.
                    report.metadata_capacity_full = true;
                    blocked_by_lookup_failure = true;
                    report.more_pending = true;
                    continue;
                }
                if remote_envelope.expires_at <= received_at / 1000 {
                    report.rejected += 1;
                    if !record_received_tombstone(
                        &mut self.profile,
                        &remote_envelope.envelope_id.clone(),
                        &envelope_hash,
                        "rejected",
                        remote_envelope.expires_at,
                        received_at,
                    ) {
                        report.metadata_capacity_full = true;
                        blocked_by_lookup_failure = true;
                        report.more_pending = true;
                        continue;
                    }
                    changed = true;
                    acknowledgements.push(delivery_ack(
                        remote_envelope.envelope_id.clone(),
                        "rejected",
                        envelope_hash,
                    ));
                    continue;
                }
                if let Some(existing) = self
                    .profile
                    .messages
                    .iter()
                    .find(|message| message.envelope_id == remote_envelope.envelope_id)
                {
                    let ack = if !existing.outgoing
                        && existing.status == "received"
                        && existing
                            .ciphertext_hash
                            .eq_ignore_ascii_case(&envelope_hash)
                    {
                        delivery_ack(
                            remote_envelope.envelope_id.clone(),
                            "delivered",
                            envelope_hash.clone(),
                        )
                    } else {
                        delivery_ack(
                            remote_envelope.envelope_id.clone(),
                            "rejected",
                            envelope_hash.clone(),
                        )
                    };
                    let outcome = if !existing.outgoing
                        && existing.status == "received"
                        && existing
                            .ciphertext_hash
                            .eq_ignore_ascii_case(&envelope_hash)
                    {
                        "delivered"
                    } else {
                        "rejected"
                    };
                    if !record_received_tombstone(
                        &mut self.profile,
                        &remote_envelope.envelope_id.clone(),
                        &envelope_hash,
                        outcome,
                        remote_envelope.expires_at,
                        received_at,
                    ) {
                        report.metadata_capacity_full = true;
                        blocked_by_lookup_failure = true;
                        report.more_pending = true;
                        continue;
                    }
                    changed = true;
                    acknowledgements.push(ack);
                    continue;
                }
                let sender_wallet = match normalize_wallet(&remote_envelope.sender_wallet) {
                    Ok(wallet) => wallet,
                    Err(_) => {
                        report.rejected += 1;
                        report.malformed += 1;
                        changed |= record_received_tombstone(
                            &mut self.profile,
                            &remote_envelope.envelope_id,
                            &envelope_hash,
                            "rejected",
                            remote_envelope.expires_at,
                            received_at,
                        );
                        acknowledgements.push(delivery_ack(
                            remote_envelope.envelope_id.clone(),
                            "rejected",
                            envelope_hash.clone(),
                        ));
                        continue;
                    }
                };
                if !peer_cache.contains_key(&sender_wallet) {
                    match self.fetch_remote_devices(&sender_wallet).await {
                        Ok(devices) => {
                            peer_cache.insert(sender_wallet.clone(), devices);
                        }
                        Err(_) => {
                            report.pending_senders.push(sender_wallet.clone());
                            blocked_by_lookup_failure = true;
                            continue;
                        }
                    }
                }
                let Some((sender_device, sender_info)) =
                    peer_cache.get(&sender_wallet).and_then(|devices| {
                        devices.iter().find(|(device, _)| {
                            device.device_id == remote_envelope.sender_device_id
                        })
                    })
                else {
                    report.pending_senders.push(sender_wallet.clone());
                    report.discarded_unverified += 1;
                    changed |= record_received_tombstone(
                        &mut self.profile,
                        &remote_envelope.envelope_id,
                        &envelope_hash,
                        "rejected",
                        remote_envelope.expires_at,
                        received_at,
                    );
                    acknowledgements.push(delivery_ack(
                        remote_envelope.envelope_id.clone(),
                        "rejected",
                        envelope_hash.clone(),
                    ));
                    continue;
                };
                if sender_info.trust != PeerTrust::Trusted {
                    report.pending_senders.push(sender_wallet.clone());
                    report.discarded_unverified += 1;
                    changed |= record_received_tombstone(
                        &mut self.profile,
                        &remote_envelope.envelope_id,
                        &envelope_hash,
                        "rejected",
                        remote_envelope.expires_at,
                        received_at,
                    );
                    acknowledgements.push(delivery_ack(
                        remote_envelope.envelope_id.clone(),
                        "rejected",
                        envelope_hash.clone(),
                    ));
                    continue;
                }
                let envelope = match serde_json::from_slice::<EncryptedEnvelope>(&envelope_bytes) {
                    Ok(value) => value,
                    Err(_) => {
                        report.rejected += 1;
                        report.malformed += 1;
                        changed |= record_received_tombstone(
                            &mut self.profile,
                            &remote_envelope.envelope_id,
                            &envelope_hash,
                            "rejected",
                            remote_envelope.expires_at,
                            received_at,
                        );
                        acknowledgements.push(delivery_ack(
                            remote_envelope.envelope_id.clone(),
                            "rejected",
                            envelope_hash.clone(),
                        ));
                        continue;
                    }
                };
                if envelope.sender_curve_key
                    != relay_client::urlsafe_to_standard(&sender_device.signed_prekey.public_key)?
                    || (envelope.message_type == 0 && remote_envelope.prekey_id.is_none())
                    || (envelope.message_type == 1 && remote_envelope.prekey_id.is_some())
                {
                    report.rejected += 1;
                    report.malformed += 1;
                    changed |= record_received_tombstone(
                        &mut self.profile,
                        &remote_envelope.envelope_id,
                        &envelope_hash,
                        "rejected",
                        remote_envelope.expires_at,
                        received_at,
                    );
                    acknowledgements.push(delivery_ack(
                        remote_envelope.envelope_id.clone(),
                        "rejected",
                        envelope_hash.clone(),
                    ));
                    continue;
                }

                if !record_received_tombstone(
                    &mut self.profile,
                    &remote_envelope.envelope_id,
                    &envelope_hash,
                    "rejected",
                    remote_envelope.expires_at,
                    received_at,
                ) {
                    report.metadata_capacity_full = true;
                    blocked_by_lookup_failure = true;
                    report.more_pending = true;
                    continue;
                }
                changed = true;
                let mut snapshot =
                    Zeroizing::new(self.account.serialize_state().map_err(|error| {
                        format!("No se pudo guardar el punto de restauración del ratchet: {error}")
                    })?);
                let decrypted = self.account.consume_message(&envelope);
                let mut decrypted = match decrypted {
                    Ok(value) => value,
                    Err(_) => {
                        self.restore_account(&snapshot)?;
                        snapshot.zeroize();
                        report.rejected += 1;
                        report.authentication_failed += 1;
                        acknowledgements.push(delivery_ack(
                            remote_envelope.envelope_id.clone(),
                            "rejected",
                            envelope_hash.clone(),
                        ));
                        continue;
                    }
                };
                let payload_result =
                    serde_json::from_slice::<ReceivedPayload>(&decrypted.plaintext);
                decrypted.plaintext.zeroize();
                let mut payload = match payload_result {
                    Ok(value) => value,
                    Err(_) => {
                        self.restore_account(&snapshot)?;
                        snapshot.zeroize();
                        report.rejected += 1;
                        report.malformed += 1;
                        acknowledgements.push(delivery_ack(
                            remote_envelope.envelope_id.clone(),
                            "rejected",
                            envelope_hash.clone(),
                        ));
                        continue;
                    }
                };
                if payload.version != 1
                    || payload.envelope_id != remote_envelope.envelope_id
                    || !payload.sender_wallet.eq_ignore_ascii_case(&sender_wallet)
                    || payload.sender_device_id != sender_device.device_id
                    || !payload.recipient_wallet.eq_ignore_ascii_case(&self.wallet)
                    || payload.recipient_device_id != self.profile.device_id
                    || payload.body.trim().is_empty()
                    || payload.body.chars().count() > 4096
                    || payload.sender_alias.chars().count() > 48
                {
                    payload.sender_alias.zeroize();
                    payload.body.zeroize();
                    self.restore_account(&snapshot)?;
                    snapshot.zeroize();
                    report.rejected += 1;
                    report.malformed += 1;
                    acknowledgements.push(delivery_ack(
                        remote_envelope.envelope_id.clone(),
                        "rejected",
                        envelope_hash.clone(),
                    ));
                    continue;
                }
                let sender_timestamp_valid = payload.sent_at > 0
                    && payload.sent_at
                        <= received_at.saturating_add(SENDER_TIMESTAMP_FUTURE_GRACE_MS);
                let cutoff = received_at.saturating_sub(LOCAL_HISTORY_RETENTION_MS);
                let retention_timestamp = if sender_timestamp_valid {
                    payload.sent_at
                } else {
                    received_at
                };
                if retention_timestamp < cutoff {
                    payload.sender_alias.zeroize();
                    payload.body.zeroize();
                    // The ciphertext was authenticated, so keep the ratchet
                    // advancement while refusing to recreate expired UI text.
                    snapshot.zeroize();
                    report.rejected += 1;
                    acknowledgements.push(delivery_ack(
                        remote_envelope.envelope_id.clone(),
                        "rejected",
                        envelope_hash.clone(),
                    ));
                    continue;
                }
                snapshot.zeroize();
                remember_conversation_wallet(&mut self.profile, &sender_wallet);
                self.profile.messages.insert(
                    0,
                    LocalChatMessage {
                        envelope_id: remote_envelope.envelope_id.clone(),
                        peer_wallet: sender_wallet.clone(),
                        peer_device_id: sender_device.device_id.clone(),
                        sender_wallet: sender_wallet.clone(),
                        sender_alias: payload.sender_alias,
                        body: payload.body,
                        created_at: payload.sent_at,
                        sender_timestamp_valid,
                        received_at: Some(received_at),
                        local_ingested_at: Some(received_at),
                        delivery_expires_at: None,
                        outgoing: false,
                        ciphertext_hash: envelope_hash.clone(),
                        status: "received".to_string(),
                        anchor_tx: None,
                        anchor_confirmed: false,
                        anchor_status: None,
                        outbox_envelope: None,
                        outbox_prekey_id: None,
                    },
                );
                self.profile.sessions.insert(
                    peer_key(&sender_wallet, &sender_device.device_id),
                    envelope.session_id.clone(),
                );
                self.profile
                    .unconfirmed_sessions
                    .remove(&envelope.session_id);
                if !update_received_tombstone_outcome(
                    &mut self.profile,
                    &remote_envelope.envelope_id,
                    "delivered",
                ) {
                    return Err("No se pudo actualizar la reserva de metadatos del inbox.".into());
                }
                let (_, cap_changed) = prune_local_profile(&mut self.profile, received_at);
                changed |= cap_changed;
                acknowledgements.push(delivery_ack(
                    remote_envelope.envelope_id.clone(),
                    "delivered",
                    envelope_hash,
                ));
                report.delivered += 1;
                changed = true;
                let _ = remote_envelope.created_at;
                let _ = remote_envelope.expires_at;
            }

            if changed {
                if let Err(error) = self.save().await {
                    self.profile.zeroize_sensitive();
                    self.profile = profile_before_batch.take();
                    let restore_result = self.restore_account(&account_before_batch);
                    restore_result?;
                    return Err(error);
                }
                self.ensure_operation_current()?;
            }
            let acked_in_batch = if acknowledgements.is_empty() {
                0
            } else {
                let receipt: AckReceipt = relay_client::call(
                    "/v1/inbox/ack",
                    "POST",
                    Some(json!({ "acknowledgments": acknowledgements })),
                    self.access_token.as_deref(),
                )
                .await?;
                self.ensure_operation_current()?;
                let acknowledged = usize::try_from(receipt.acknowledged).unwrap_or(usize::MAX);
                report.acknowledged = report.acknowledged.saturating_add(acknowledged);
                acknowledged
            };
            if blocked_by_lookup_failure || acked_in_batch == 0 {
                report.more_pending = true;
                keep_scanning = false;
            } else if batch_index + 1 == MAX_REFRESH_BATCHES && batch_len == 50 {
                report.more_pending = true;
            } else if batch_len < 50 {
                keep_scanning = false;
            }
        }
        self.ensure_operation_current()?;
        report.pending_senders.sort();
        report.pending_senders.dedup();
        self.pending_senders = report.pending_senders.clone();
        Ok(report)
    }

    pub async fn refresh_delivery_statuses(&mut self) -> Result<usize, String> {
        self.ensure_operation_current()?;
        let token = self.access_token.as_deref().ok_or_else(|| {
            "Registra este dispositivo antes de consultar recibos de entrega.".to_string()
        })?;
        let envelope_ids = self
            .profile
            .messages
            .iter()
            .filter(|message| {
                message.outgoing
                    && message.outbox_envelope.is_some()
                    && matches!(
                        message.status.as_str(),
                        "waiting_online" | "awaiting_delivery" | "queued" | "sent"
                    )
            })
            .take(50)
            .map(|message| message.envelope_id.clone())
            .collect::<Vec<_>>();
        if envelope_ids.is_empty() {
            return Ok(0);
        }
        let requested_ids = envelope_ids.iter().cloned().collect::<BTreeSet<_>>();
        let response: DeliveryStatusResponse = relay_client::call(
            "/v1/messages/status",
            "POST",
            Some(
                serde_json::to_value(DeliveryStatusRequest { envelope_ids }).map_err(|error| {
                    format!("No se pudo preparar la consulta de entrega: {error}")
                })?,
            ),
            Some(token),
        )
        .await?;
        self.ensure_operation_current()?;
        let now = timestamp_ms() / 1000;
        let mut changed = false;
        let mut updated = 0usize;
        let returned_ids = response
            .statuses
            .iter()
            .map(|receipt| receipt.envelope_id.clone())
            .collect::<BTreeSet<_>>();
        for remote in response.statuses {
            let Some(message) = self
                .profile
                .messages
                .iter_mut()
                .find(|message| message.outgoing && message.envelope_id == remote.envelope_id)
            else {
                continue;
            };
            if message.outbox_envelope.is_none() {
                continue;
            }
            if remote.expires_at > 0 && message.delivery_expires_at != Some(remote.expires_at) {
                message.delivery_expires_at = Some(remote.expires_at);
                changed = true;
            }
            let Some(next_status) =
                classify_delivery_receipt(&remote, &message.ciphertext_hash, now)
            else {
                continue;
            };
            if next_status == "delivered" {
                if let Some(received_at) = remote.delivered_at.and_then(relay_ack_timestamp_ms) {
                    if message.received_at != Some(received_at) {
                        message.received_at = Some(received_at);
                        changed = true;
                    }
                }
            }
            if message.status != next_status {
                message.status = next_status.to_string();
                changed = true;
                updated = updated.saturating_add(1);
            }
            if matches!(
                next_status,
                "delivered" | "rejected" | "expired" | "integrity_error" | "integrity_unverified"
            ) {
                message.outbox_envelope = None;
                message.outbox_prekey_id = None;
                changed = true;
            }
        }
        for message in &mut self.profile.messages {
            if !message.outgoing
                || message.outbox_envelope.is_none()
                || !requested_ids.contains(&message.envelope_id)
                || returned_ids.contains(&message.envelope_id)
                || !relay_envelope_expired(
                    message.delivery_expires_at,
                    message.created_at,
                    now,
                    true,
                )
            {
                continue;
            }
            message.status = "expired".to_string();
            message.outbox_envelope = None;
            message.outbox_prekey_id = None;
            changed = true;
            updated = updated.saturating_add(1);
        }
        if changed {
            self.save().await?;
            self.ensure_operation_current()?;
        }
        Ok(updated)
    }

    pub async fn set_anchor_tx(
        &mut self,
        envelope_id: &str,
        tx_hash: &str,
        status: &str,
    ) -> Result<(), String> {
        self.ensure_operation_current()?;
        if !matches!(status, "confirmed" | "pending" | "failed" | "unknown") {
            return Err("El estado de anclaje local no es válido.".into());
        }
        let message = self
            .profile
            .messages
            .iter_mut()
            .find(|message| message.envelope_id == envelope_id)
            .ok_or_else(|| {
                "No se encontró el mensaje local para actualizar su anclaje.".to_string()
            })?;
        message.anchor_tx = Some(tx_hash.to_string());
        message.anchor_confirmed = status == "confirmed";
        message.anchor_status = Some(status.to_string());
        self.save().await
    }

    async fn fetch_remote_devices(
        &self,
        wallet: &str,
    ) -> Result<Vec<(RemoteDevice, PeerDeviceInfo)>, String> {
        let wallet = normalize_wallet(wallet)?;
        let response: DeviceBundles =
            relay_client::call(&format!("/v1/bundles/{wallet}"), "GET", None, None).await?;
        self.ensure_operation_current()?;
        if !response.wallet.eq_ignore_ascii_case(&wallet) {
            return Err("El relay devolvió bundles para una wallet distinta.".into());
        }
        let mut result = Vec::with_capacity(response.devices.len());
        for raw_device in response.devices {
            let Ok(device) = serde_json::from_value::<RemoteDevice>(raw_device) else {
                continue;
            };
            if !device.wallet.eq_ignore_ascii_case(&wallet) {
                continue;
            }
            if verify_remote_device(&device).await.is_err() {
                continue;
            }
            let key = peer_key(&wallet, &device.device_id);
            let trust = match self.profile.trusted_fingerprints.get(&key) {
                Some(known) if known.eq_ignore_ascii_case(&device.identity_key_hash) => {
                    PeerTrust::Trusted
                }
                Some(_) => PeerTrust::Changed,
                None => PeerTrust::FirstUse,
            };
            let online = if let Some(token) = self.access_token.as_deref() {
                let response: Result<PresenceReceipt, String> = relay_client::call(
                    "/v1/presence/check",
                    "POST",
                    Some(json!({
                        "wallet": wallet,
                        "device_id": device.device_id,
                    })),
                    Some(token),
                )
                .await;
                self.ensure_operation_current()?;
                response
                    .ok()
                    .map(|receipt| receipt.online && receipt.expires_at > receipt.checked_at)
            } else {
                None
            };
            let info = PeerDeviceInfo {
                wallet: wallet.clone(),
                device_id: device.device_id.clone(),
                identity_key_hash: device.identity_key_hash.clone(),
                fingerprint: format_fingerprint(&device.identity_key_hash),
                trust,
                available_prekeys: device.available_one_time_prekeys,
                online,
            };
            result.push((device, info));
        }
        Ok(result)
    }

    async fn save(&mut self) -> Result<(), String> {
        self.ensure_operation_current()?;
        let _ = prune_local_profile(&mut self.profile, timestamp_ms());
        let account_state = self.account.serialize_state().map_err(|error| {
            format!("No se pudo serializar el estado privado del ratchet: {error}")
        })?;
        let mut persisted = PersistedProfile {
            version: PROFILE_VERSION,
            device_id: self.profile.device_id.clone(),
            self_alias: self.profile.self_alias.clone(),
            sessions: self.profile.sessions.clone(),
            trusted_fingerprints: self.profile.trusted_fingerprints.clone(),
            generated_prekey_ids: self.profile.generated_prekey_ids.clone(),
            unconfirmed_sessions: self.profile.unconfirmed_sessions.clone(),
            conversation_wallets: self.profile.conversation_wallets.clone(),
            received_envelope_tombstones: self.profile.received_envelope_tombstones.clone(),
            messages: self.profile.messages.clone(),
            account_state,
        };
        let mut serialized = Zeroizing::new(Vec::new());
        let serialized_result = serde_json::to_writer(&mut *serialized, &persisted)
            .map_err(|error| format!("No se pudo serializar el perfil local: {error}"));
        persisted.zeroize_sensitive();
        serialized_result?;
        let encrypted = encrypt_private_state(serialized.as_slice(), self.password.as_str())
            .map_err(|error| format!("No se pudo cifrar el perfil local: {error}"))?;
        let mut encoded = serde_json::to_string(&encrypted)
            .map_err(|error| format!("No se pudo codificar el estado cifrado: {error}"))?;
        let result = secure_storage::save_encrypted_state(&self.wallet, &encoded).await;
        encoded.zeroize();
        result?;
        self.ensure_operation_current()
    }

    fn restore_account(&mut self, state: &[u8]) -> Result<(), String> {
        self.account = SecureAccount::deserialize_state(state).map_err(|error| {
            format!("No se pudo restaurar el ratchet tras un mensaje inválido: {error}")
        })?;
        Ok(())
    }
}

fn prune_local_profile(profile: &mut LocalProfile, now_ms: i64) -> (usize, bool) {
    let now_ms = now_ms.max(0);
    let cutoff = now_ms.saturating_sub(LOCAL_HISTORY_RETENTION_MS);
    let mut changed = normalize_conversation_index(profile);

    // A future or unavailable sent_at cannot be allowed to live forever. New
    // incoming messages carry local_ingested_at; this also repairs old
    // profiles once, then persists the local first-seen time.
    for message in &mut profile.messages {
        if message.local_ingested_at.is_none()
            && (message.created_at <= 0 || message.created_at > now_ms)
        {
            message.local_ingested_at = message.received_at.filter(|value| *value <= now_ms);
            if message.local_ingested_at.is_none() {
                message.local_ingested_at = Some(now_ms);
            }
            changed = true;
        }
    }

    let mut removed = 0usize;
    let mut retained = Vec::with_capacity(profile.messages.len().min(MAX_MESSAGES));
    for mut message in std::mem::take(&mut profile.messages) {
        if local_message_age_timestamp(&message, now_ms) < cutoff {
            zeroize_local_message(&mut message);
            removed = removed.saturating_add(1);
            changed = true;
        } else {
            retained.push(message);
        }
    }
    while retained.len() > MAX_MESSAGES {
        if let Some(oldest_index) = retained
            .iter()
            .enumerate()
            .min_by_key(|(_, message)| local_message_age_timestamp(message, now_ms))
            .map(|(index, _)| index)
        {
            let mut message = retained.remove(oldest_index);
            zeroize_local_message(&mut message);
            removed = removed.saturating_add(1);
            changed = true;
        }
    }
    profile.messages = retained;

    changed |= prune_received_tombstones(profile, now_ms);
    (removed, changed)
}

fn prune_received_tombstones(profile: &mut LocalProfile, now_ms: i64) -> bool {
    let now_seconds = now_ms.max(0) / 1000;
    let mut changed = false;
    let mut retained = Vec::with_capacity(profile.received_envelope_tombstones.len());
    for mut tombstone in std::mem::take(&mut profile.received_envelope_tombstones) {
        if tombstone.expires_at <= 0 {
            let fallback = if tombstone.recorded_at > 0 {
                tombstone.recorded_at / 1000
            } else {
                now_seconds
            };
            tombstone.expires_at = fallback.saturating_add(RELAY_ENVELOPE_TTL_SECONDS);
            changed = true;
        }
        let keep = now_seconds
            < tombstone
                .expires_at
                .saturating_add(RELAY_EXPIRY_GRACE_SECONDS);
        if keep {
            retained.push(tombstone);
        } else {
            zeroize_tombstone(&mut tombstone);
            changed = true;
        }
    }
    profile.received_envelope_tombstones = retained;
    changed
}

fn local_message_age_timestamp(message: &LocalChatMessage, now_ms: i64) -> i64 {
    if message
        .local_ingested_at
        .is_some_and(|ingested| message.created_at > ingested)
    {
        // A sender-controlled future timestamp must not become the retention
        // anchor after the local first-seen timestamp has been recorded.
        message
            .local_ingested_at
            .filter(|value| *value > 0 && *value <= now_ms)
            .unwrap_or(now_ms)
    } else if message.created_at > 0 && message.created_at <= now_ms {
        message.created_at
    } else if message.created_at > now_ms {
        message
            .local_ingested_at
            .or(message.received_at)
            .filter(|value| *value > 0 && *value <= now_ms)
            .unwrap_or(now_ms)
    } else {
        message
            .local_ingested_at
            .or(message.received_at)
            .filter(|value| *value > 0 && *value <= now_ms)
            .unwrap_or(now_ms)
    }
}

fn zeroize_local_message(message: &mut LocalChatMessage) {
    message.envelope_id.zeroize();
    message.peer_wallet.zeroize();
    message.peer_device_id.zeroize();
    message.sender_wallet.zeroize();
    message.sender_alias.zeroize();
    message.body.zeroize();
    message.ciphertext_hash.zeroize();
    message.status.zeroize();
    message.anchor_tx.zeroize();
    message.anchor_status.zeroize();
    message.outbox_envelope.zeroize();
    message.outbox_envelope = None;
    message.outbox_prekey_id.zeroize();
    message.outbox_prekey_id = None;
}

fn zeroize_tombstone(tombstone: &mut ReceivedEnvelopeTombstone) {
    tombstone.envelope_id.zeroize();
    tombstone.ciphertext_hash.zeroize();
    tombstone.outcome.zeroize();
}

fn normalize_conversation_index(profile: &mut LocalProfile) -> bool {
    let original = profile.conversation_wallets.clone();
    let mut normalized = Vec::with_capacity(MAX_CONVERSATION_WALLETS);
    for wallet in std::mem::take(&mut profile.conversation_wallets)
        .into_iter()
        .chain(
            profile
                .messages
                .iter()
                .map(|message| message.peer_wallet.clone()),
        )
    {
        let Ok(wallet) = normalize_wallet(&wallet) else {
            continue;
        };
        if wallet.eq_ignore_ascii_case("0x0000000000000000000000000000000000000000")
            || normalized.iter().any(|item: &String| item == &wallet)
        {
            continue;
        }
        normalized.push(wallet);
        if normalized.len() == MAX_CONVERSATION_WALLETS {
            break;
        }
    }
    profile.conversation_wallets = normalized;
    profile.conversation_wallets != original
}

fn remember_conversation_wallet(profile: &mut LocalProfile, wallet: &str) {
    let Ok(wallet) = normalize_wallet(wallet) else {
        return;
    };
    profile
        .conversation_wallets
        .retain(|existing| !existing.eq_ignore_ascii_case(&wallet));
    profile.conversation_wallets.insert(0, wallet);
    profile
        .conversation_wallets
        .truncate(MAX_CONVERSATION_WALLETS);
}

fn record_received_tombstone(
    profile: &mut LocalProfile,
    envelope_id: &str,
    ciphertext_hash: &str,
    outcome: &str,
    expires_at: i64,
    recorded_at_ms: i64,
) -> bool {
    // Never evict a still-live tombstone just to accept another one. If the
    // bounded metadata budget is full, callers must leave the relay row
    // pending. Oversized legacy profiles remain fail-closed until expiry
    // releases exact capacity.
    if profile
        .received_envelope_tombstones
        .iter()
        .any(|item| item.envelope_id == envelope_id)
    {
        return false;
    }
    if profile.received_envelope_tombstones.len() >= MAX_RECEIVED_TOMBSTONES {
        return false;
    }
    profile
        .received_envelope_tombstones
        .push(ReceivedEnvelopeTombstone {
            envelope_id: envelope_id.to_string(),
            ciphertext_hash: ciphertext_hash.to_string(),
            outcome: outcome.to_string(),
            expires_at: if expires_at > 0 {
                expires_at
            } else {
                (recorded_at_ms / 1000).saturating_add(RELAY_ENVELOPE_TTL_SECONDS)
            },
            recorded_at: recorded_at_ms,
        });
    true
}

fn reserve_tombstone_capacity(profile: &mut LocalProfile, now_ms: i64) -> bool {
    let _ = prune_received_tombstones(profile, now_ms);
    profile.received_envelope_tombstones.len() < MAX_RECEIVED_TOMBSTONES
}

fn update_received_tombstone_outcome(
    profile: &mut LocalProfile,
    envelope_id: &str,
    outcome: &str,
) -> bool {
    let Some(tombstone) = profile
        .received_envelope_tombstones
        .iter_mut()
        .find(|item| item.envelope_id == envelope_id)
    else {
        return false;
    };
    tombstone.outcome = outcome.to_string();
    true
}

fn tombstone_ack_outcome(
    tombstone: &ReceivedEnvelopeTombstone,
    ciphertext_hash: &str,
) -> &'static str {
    if tombstone.outcome == "delivered"
        && tombstone
            .ciphertext_hash
            .eq_ignore_ascii_case(ciphertext_hash)
    {
        "delivered"
    } else {
        "rejected"
    }
}

#[derive(Debug, Deserialize)]
struct ReceivedPayload {
    version: u8,
    envelope_id: String,
    sender_wallet: String,
    sender_device_id: String,
    recipient_wallet: String,
    recipient_device_id: String,
    sender_alias: String,
    sent_at: i64,
    body: String,
}

fn verify_challenge_shape(
    challenge: &AuthChallenge,
    wallet: &str,
    device_id: &str,
    identity_hash: &str,
) -> Result<(), String> {
    let now = u64::try_from(timestamp_ms().max(0) / 1000).unwrap_or(0);
    verify_challenge_shape_at(challenge, wallet, device_id, identity_hash, now)
}

fn verify_challenge_shape_at(
    challenge: &AuthChallenge,
    wallet: &str,
    device_id: &str,
    identity_hash: &str,
    now: u64,
) -> Result<(), String> {
    let data = &challenge.typed_data;
    let message = &data["message"];
    if data["primaryType"] != "IdentityKeyBinding"
        || data["domain"]["name"] != "NODO Secure Messaging"
        || data["domain"]["version"] != "1"
        || data["domain"]["chainId"].as_u64() != Some(11155111)
        || !message["wallet"]
            .as_str()
            .is_some_and(|value| value.eq_ignore_ascii_case(wallet))
        || message["deviceId"] != device_id
        || !message["identityKeyHash"]
            .as_str()
            .is_some_and(|value| value.eq_ignore_ascii_case(identity_hash))
        || message["nonce"] != challenge.nonce
        || message["expiresAt"].as_u64() != Some(challenge.binding_expires_at)
        || challenge.challenge_id.is_empty()
    {
        return Err("El relay devolvió un challenge EIP-712 distinto del formato NODO esperado; no se pidió firma.".into());
    }
    if challenge.expires_at <= now || challenge.binding_expires_at <= now {
        return Err("El challenge EIP-712 venció o el reloj del dispositivo está adelantado. Sincroniza fecha y hora y vuelve a vincular; no se pidió firma.".into());
    }
    if !auth_expiry_is_valid_at(challenge.expires_at, now, MAX_CHALLENGE_TTL_SECONDS)
        || !auth_expiry_is_valid_at(challenge.binding_expires_at, now, MAX_BINDING_TTL_SECONDS)
    {
        return Err("El challenge EIP-712 excede la vigencia permitida o el reloj del dispositivo está atrasado más de 60 segundos. Sincroniza fecha y hora y vuelve a vincular; no se pidió firma.".into());
    }
    Ok(())
}

fn auth_expiry_is_valid_at(expires_at: u64, now: u64, max_ttl: u64) -> bool {
    // Small server-ahead clock skew must not block a valid identity binding.
    // Never relax the expired lower bound; the relay also checks its own clock.
    expires_at > now
        && expires_at
            <= now
                .saturating_add(max_ttl)
                .saturating_add(AUTH_CLOCK_SKEW_SECONDS)
}

async fn verify_remote_device(device: &RemoteDevice) -> Result<(), String> {
    if device.signed_prekey.key_id != IDENTITY_PREKEY_ID {
        return Err(
            "El dispositivo remoto usa una clave de identidad con formato no compatible.".into(),
        );
    }
    let ed25519_key = relay_client::urlsafe_to_standard(&device.identity_key)?;
    let identity_key_bytes = vodozemac::base64_decode(&ed25519_key)
        .map_err(|error| format!("La clave de identidad remota no es válida: {error}"))?;
    if identity_key_bytes.len() != 32 {
        return Err("La clave de identidad remota no tiene 32 bytes.".into());
    }
    let hash = format!(
        "0x{}",
        hex::encode(digest(&SHA256, &identity_key_bytes).as_ref())
    );
    if !hash.eq_ignore_ascii_case(&device.identity_key_hash) {
        return Err("La huella del relay no coincide con su clave de identidad pública.".into());
    }
    let curve25519_key = relay_client::urlsafe_to_standard(&device.signed_prekey.public_key)?;
    let identity_signature = relay_client::urlsafe_to_standard(&device.signed_prekey.signature)?;
    let proof = PublicDeviceIdentity {
        ed25519_key: ed25519_key.clone(),
        curve25519_key,
        signature: identity_signature,
    };
    proof.verify().map_err(|error| {
        format!("La firma Ed25519 de la identidad remota no es válida: {error}")
    })?;
    let expires_at = u64::try_from(device.binding_expires_at)
        .map_err(|_| "La atestación wallet-key remota tiene expiración inválida.".to_string())?;
    let now = u64::try_from(timestamp_ms().max(0) / 1000).unwrap_or(0);
    if !auth_expiry_is_valid_at(expires_at, now, MAX_BINDING_TTL_SECONDS) {
        return Err(
            "La atestación wallet-key remota está vencida o tiene una vigencia inválida.".into(),
        );
    }
    let binding = IdentityKeyBinding {
        wallet: device.wallet.clone(),
        device_id: device.device_id.clone(),
        identity_key_hash: device.identity_key_hash.clone(),
        nonce: device.binding_nonce.clone(),
        expires_at,
    };
    let valid =
        wallet_bridge::verify_identity_key_binding(&binding, &device.binding_signature).await?;
    if !valid {
        return Err("La firma EIP-712 no vincula esta clave con la wallet publicada.".into());
    }
    Ok(())
}

fn normalize_wallet(wallet: &str) -> Result<String, String> {
    if wallet.len() != 42
        || !wallet.starts_with("0x")
        || !wallet[2..]
            .chars()
            .all(|character| character.is_ascii_hexdigit())
    {
        return Err(
            "La dirección debe tener el formato EVM 0x + 40 caracteres hexadecimales.".into(),
        );
    }
    Ok(wallet.to_ascii_lowercase())
}

fn peer_key(wallet: &str, device_id: &str) -> String {
    format!("{}|{}", wallet.to_ascii_lowercase(), device_id)
}

fn is_expired_prekey_reservation(error: &str) -> bool {
    error.contains("claim expired")
        || error.contains("claim has expired")
        || error.contains("initial envelope has already expired")
}

fn is_expired_relay_envelope(error: &str) -> bool {
    error.contains("envelope_id has expired and cannot be replayed")
        || error.contains("envelope_id was already used or expired")
}

fn is_relay_integrity_error(error: &str) -> bool {
    error.starts_with("relay-integrity-error:")
}

fn relay_http_status(error: &str) -> Option<u16> {
    let code = error
        .split_once("HTTP ")?
        .1
        .chars()
        .take_while(char::is_ascii_digit)
        .collect::<String>();
    code.parse().ok()
}

fn is_permanent_relay_error(error: &str) -> bool {
    if is_expired_prekey_reservation(error) || is_expired_relay_envelope(error) {
        return false;
    }
    match relay_http_status(error) {
        Some(401) | Some(408) | Some(425) | Some(429) => false,
        Some(400..=499) => true,
        _ => false,
    }
}

fn delivery_ack(
    envelope_id: String,
    outcome: &str,
    ciphertext_hash: String,
) -> DeliveryAcknowledgment {
    DeliveryAcknowledgment {
        envelope_id,
        outcome: outcome.to_string(),
        ciphertext_hash,
    }
}

fn relay_ack_timestamp_ms(seconds: i64) -> Option<i64> {
    let timestamp_ms = seconds.checked_mul(1000)?;
    (seconds > 0 && timestamp_ms <= 8_640_000_000_000_000).then_some(timestamp_ms)
}

fn relay_envelope_expired(
    relay_expires_at: Option<i64>,
    created_at_ms: i64,
    now_seconds: i64,
    track_local_outbox: bool,
) -> bool {
    let expires_at = relay_expires_at
        .filter(|expires_at| *expires_at > 0)
        .or_else(|| {
            (track_local_outbox && created_at_ms > 0)
                .then(|| (created_at_ms / 1000).saturating_add(RELAY_ENVELOPE_TTL_SECONDS))
        });
    expires_at.is_some_and(|expires_at| {
        now_seconds >= expires_at.saturating_add(RELAY_EXPIRY_GRACE_SECONDS)
    })
}

fn classify_delivery_receipt(
    receipt: &DeliveryStatusRecord,
    expected_ciphertext_hash: &str,
    now: i64,
) -> Option<&'static str> {
    if receipt.expires_at <= 0 {
        return Some("integrity_unverified");
    }
    let Some(receipt_hash) = receipt.ciphertext_hash.as_deref() else {
        return Some("integrity_unverified");
    };
    if !receipt_hash.eq_ignore_ascii_case(expected_ciphertext_hash) {
        return Some("integrity_error");
    }
    match receipt.status.as_str() {
        "queued" => {
            if receipt.delivered_at.is_some() {
                return Some("integrity_error");
            }
            if relay_envelope_expired(Some(receipt.expires_at), 0, now, true) {
                return Some("expired");
            }
            if receipt.recipient_online {
                Some("awaiting_delivery")
            } else {
                Some("waiting_online")
            }
        }
        "delivered" | "rejected" => {
            let Some(delivered_at) = receipt.delivered_at else {
                return Some("integrity_error");
            };
            if delivered_at <= 0
                || delivered_at > now.saturating_add(60)
                || delivered_at >= receipt.expires_at
            {
                return Some("integrity_error");
            }
            if receipt.status == "delivered" {
                Some("delivered")
            } else {
                Some("rejected")
            }
        }
        _ => Some("integrity_unverified"),
    }
}

fn format_fingerprint(hash: &str) -> String {
    let raw = hash.strip_prefix("0x").unwrap_or(hash);
    raw.as_bytes()
        .chunks(4)
        .map(|chunk| std::str::from_utf8(chunk).unwrap_or_default())
        .collect::<Vec<_>>()
        .join(" ")
}

fn timestamp_ms() -> i64 {
    #[cfg(target_arch = "wasm32")]
    {
        js_sys::Date::now() as i64
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64
    }
}

fn keccak_hex(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(Keccak256::digest(bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;

    const AUTH_TEST_WALLET: &str = "0x0000000000000000000000000000000000000001";
    const AUTH_TEST_DEVICE: &str = "11111111-1111-4111-8111-111111111111";
    const AUTH_TEST_NOW: u64 = 1_800_000_000;

    fn local_message_fixture(
        envelope_id: &str,
        peer_wallet: &str,
        created_at: i64,
        body: &str,
    ) -> LocalChatMessage {
        LocalChatMessage {
            envelope_id: envelope_id.to_string(),
            peer_wallet: peer_wallet.to_string(),
            peer_device_id: "33333333-3333-4333-8333-333333333333".to_string(),
            sender_wallet: AUTH_TEST_WALLET.to_string(),
            sender_alias: "fixture-alias".to_string(),
            body: body.to_string(),
            created_at,
            sender_timestamp_valid: created_at > 0,
            received_at: None,
            local_ingested_at: None,
            delivery_expires_at: None,
            outgoing: true,
            ciphertext_hash: "0xfixture".to_string(),
            status: "queued".to_string(),
            anchor_tx: None,
            anchor_confirmed: false,
            anchor_status: None,
            outbox_envelope: Some("opaque-retry-ciphertext".to_string()),
            outbox_prekey_id: Some("otk-fixture".to_string()),
        }
    }

    fn auth_challenge_fixture(server_now: u64) -> AuthChallenge {
        let binding_expiry = server_now + MAX_BINDING_TTL_SECONDS;
        // Match the relay's JSON integer representation, including a JSON round trip.
        serde_json::from_value(json!({
            "challenge_id": "22222222-2222-4222-8222-222222222222",
            "nonce": "public-test-nonce",
            "expires_at": server_now + MAX_CHALLENGE_TTL_SECONDS,
            "binding_expires_at": binding_expiry,
            "typed_data": {
                "primaryType": "IdentityKeyBinding",
                "domain": { "name": "NODO Secure Messaging", "version": "1", "chainId": 11155111_u64 },
                "message": {
                    "wallet": AUTH_TEST_WALLET,
                    "deviceId": AUTH_TEST_DEVICE,
                    "identityKeyHash": format!("0x{}", "22".repeat(32)),
                    "nonce": "public-test-nonce",
                    "expiresAt": binding_expiry
                }
            }
        })).expect("server-shaped authentication challenge")
    }

    fn verify_auth_fixture(challenge: &AuthChallenge, now: u64) -> Result<(), String> {
        verify_challenge_shape_at(
            challenge,
            AUTH_TEST_WALLET,
            AUTH_TEST_DEVICE,
            &format!("0x{}", "22".repeat(32)),
            now,
        )
    }

    #[test]
    fn valid_auth_challenge_tolerates_only_bounded_server_ahead_clock_skew() {
        for skew in [0, 1, AUTH_CLOCK_SKEW_SECONDS] {
            let challenge = auth_challenge_fixture(AUTH_TEST_NOW + skew);
            if skew > 0 {
                // This legitimate case failed the previous exact upper bound.
                assert!(challenge.expires_at > AUTH_TEST_NOW + MAX_CHALLENGE_TTL_SECONDS);
                assert!(challenge.binding_expires_at > AUTH_TEST_NOW + MAX_BINDING_TTL_SECONDS);
            }
            assert!(verify_auth_fixture(&challenge, AUTH_TEST_NOW).is_ok());
        }
        let too_far = auth_challenge_fixture(AUTH_TEST_NOW + AUTH_CLOCK_SKEW_SECONDS + 1);
        assert!(verify_auth_fixture(&too_far, AUTH_TEST_NOW)
            .unwrap_err()
            .contains("60 segundos"));
    }

    #[test]
    fn authentication_never_signs_expired_or_overlong_challenges() {
        let challenge = auth_challenge_fixture(AUTH_TEST_NOW);
        assert!(verify_auth_fixture(&challenge, challenge.expires_at)
            .unwrap_err()
            .contains("venció"));
        assert!(verify_auth_fixture(&challenge, challenge.expires_at + 1).is_err());
        let mut overlong_binding = auth_challenge_fixture(AUTH_TEST_NOW);
        overlong_binding.binding_expires_at += AUTH_CLOCK_SKEW_SECONDS + 1;
        overlong_binding.typed_data["message"]["expiresAt"] =
            json!(overlong_binding.binding_expires_at);
        assert!(verify_auth_fixture(&overlong_binding, AUTH_TEST_NOW).is_err());
        let mut overlong_challenge = auth_challenge_fixture(AUTH_TEST_NOW);
        overlong_challenge.expires_at += AUTH_CLOCK_SKEW_SECONDS + 1;
        assert!(verify_auth_fixture(&overlong_challenge, AUTH_TEST_NOW).is_err());
    }

    #[test]
    fn auth_clock_tolerance_never_allows_identity_or_json_type_substitutions() {
        let valid = auth_challenge_fixture(AUTH_TEST_NOW + 1);
        for (pointer, replacement) in [
            ("/primaryType", json!("OtherBinding")),
            ("/domain/name", json!("Other app")),
            ("/domain/version", json!("2")),
            ("/domain/chainId", json!(1)),
            ("/domain/chainId", json!("11155111")),
            ("/domain/chainId", json!(11155111.0)),
            (
                "/message/wallet",
                json!("0x0000000000000000000000000000000000000002"),
            ),
            ("/message/deviceId", json!("another-device")),
            (
                "/message/identityKeyHash",
                json!(format!("0x{}", "33".repeat(32))),
            ),
            ("/message/nonce", json!("another-nonce")),
            (
                "/message/expiresAt",
                json!(valid.binding_expires_at.to_string()),
            ),
            ("/message/expiresAt", json!(valid.binding_expires_at + 1)),
            ("/message/expiresAt", Value::Null),
        ] {
            let mut challenge = auth_challenge_fixture(AUTH_TEST_NOW + 1);
            *challenge
                .typed_data
                .pointer_mut(pointer)
                .expect("fixture field") = replacement;
            assert!(
                verify_auth_fixture(&challenge, AUTH_TEST_NOW)
                    .unwrap_err()
                    .contains("formato"),
                "{pointer}"
            );
        }
        let mut challenge = auth_challenge_fixture(AUTH_TEST_NOW);
        challenge.challenge_id.clear();
        assert!(verify_auth_fixture(&challenge, AUTH_TEST_NOW).is_err());
    }

    #[test]
    fn remote_binding_expiry_uses_the_same_bounded_clock_policy() {
        for ttl in [MAX_CHALLENGE_TTL_SECONDS, MAX_BINDING_TTL_SECONDS] {
            assert!(auth_expiry_is_valid_at(
                AUTH_TEST_NOW + ttl + AUTH_CLOCK_SKEW_SECONDS,
                AUTH_TEST_NOW,
                ttl
            ));
            assert!(!auth_expiry_is_valid_at(
                AUTH_TEST_NOW + ttl + AUTH_CLOCK_SKEW_SECONDS + 1,
                AUTH_TEST_NOW,
                ttl
            ));
            assert!(!auth_expiry_is_valid_at(AUTH_TEST_NOW, AUTH_TEST_NOW, ttl));
        }
    }

    #[test]
    fn delivered_and_rejected_acknowledgments_always_include_the_ciphertext_hash() {
        let hash = keccak_hex(b"opaque ciphertext bytes");
        for outcome in ["delivered", "rejected"] {
            let ack = delivery_ack("envelope-id".into(), outcome, hash.clone());
            let value = serde_json::to_value(ack).expect("ACK JSON");
            assert_eq!(value["outcome"], outcome);
            assert_eq!(value["ciphertext_hash"], hash);
            assert!(!value.to_string().contains("opaque ciphertext bytes"));
        }
    }

    #[test]
    fn legacy_local_message_without_receipt_or_expiry_fields_remains_readable() {
        let legacy: LocalChatMessage = serde_json::from_value(serde_json::json!({
            "envelope_id": "legacy-envelope",
            "peer_wallet": "0x2222222222222222222222222222222222222222",
            "peer_device_id": "peer-device",
            "sender_wallet": "0x1111111111111111111111111111111111111111",
            "sender_alias": "Alice",
            "body": "readable after decryption",
            "created_at": 1_797_590_000_000_i64,
            "outgoing": false,
            "ciphertext_hash": "0xabc",
            "status": "received",
            "anchor_tx": null
        }))
        .expect("legacy message remains readable");
        assert_eq!(legacy.body, "readable after decryption");
        assert_eq!(legacy.received_at, None);
        assert_eq!(legacy.delivery_expires_at, None);
    }

    #[test]
    fn relay_ack_seconds_convert_to_valid_utc_milliseconds_only() {
        assert_eq!(
            relay_ack_timestamp_ms(1_797_590_000),
            Some(1_797_590_000_000)
        );
        assert_eq!(relay_ack_timestamp_ms(0), None);
        assert_eq!(relay_ack_timestamp_ms(i64::MAX), None);
    }

    #[test]
    fn relay_expiry_uses_server_deadline_grace_and_conservative_local_fallback() {
        assert!(!relay_envelope_expired(Some(1_000), 1_000_000, 1_059, true));
        assert!(relay_envelope_expired(Some(1_000), 1_000_000, 1_060, true));
        assert!(!relay_envelope_expired(None, 1_000_000, 605_859, true));
        assert!(relay_envelope_expired(None, 1_000_000, 605_860, true));
        assert!(!relay_envelope_expired(None, 1_000_000, 605_860, false));
        assert!(!relay_envelope_expired(None, 0, 605_860, true));
    }

    #[test]
    fn permanent_http_errors_are_terminal_but_transient_and_prekey_errors_retry() {
        assert!(is_permanent_relay_error(
            "HTTP 404: recipient device not found"
        ));
        assert!(is_permanent_relay_error(
            "HTTP 409: ciphertext hash mismatch"
        ));
        assert!(!is_permanent_relay_error("HTTP 401: session expired"));
        assert!(!is_permanent_relay_error("HTTP 408: request timeout"));
        assert!(!is_permanent_relay_error("HTTP 425: too early"));
        assert!(!is_permanent_relay_error("HTTP 429: rate limited"));
        assert!(!is_permanent_relay_error("HTTP 503: unavailable"));
        assert!(!is_permanent_relay_error(
            "HTTP 409: one-time prekey claim expired or was already consumed"
        ));
        assert!(!is_permanent_relay_error("network error: fetch failed"));
    }

    #[test]
    fn message_body_and_alias_are_only_inside_ciphertext() {
        let mut alice = SecureAccount::new();
        let mut bob = SecureAccount::new();
        let bob_bundle = bob.public_prekey_bundle().expect("Bob public bundle");
        let session_id = alice
            .create_outbound_session_from_bundle(&bob_bundle)
            .expect("Alice outbound session");
        let payload = MessagePayload {
            version: 1,
            envelope_id: "envelope-test-1",
            sender_wallet: "0x1111111111111111111111111111111111111111",
            sender_device_id: "alice-device",
            recipient_wallet: "0x2222222222222222222222222222222222222222",
            recipient_device_id: "bob-device",
            sender_alias: "Blue Lantern",
            sent_at: 1_797_590_000,
            body: "confidential sample body",
        };
        let envelope = alice
            .encrypt_json(&session_id, &payload)
            .expect("encrypted envelope");
        let encoded = serde_json::to_string(&envelope).expect("serialize ciphertext");

        assert!(!encoded.contains("Blue Lantern"));
        assert!(!encoded.contains("confidential sample body"));

        let mut decrypted = bob.consume_message(&envelope).expect("decrypt envelope");
        let decoded: Value = serde_json::from_slice(&decrypted.plaintext).expect("payload JSON");
        assert_eq!(decoded["sender_alias"], "Blue Lantern");
        assert_eq!(decoded["body"], "confidential sample body");
        decrypted.plaintext.zeroize();
    }

    #[test]
    fn expired_prekey_reservation_matches_relay_errors_only() {
        assert!(is_expired_prekey_reservation(
            "one-time prekey claim expired or was already consumed"
        ));
        assert!(is_expired_prekey_reservation(
            "the initial envelope has already expired"
        ));
        assert!(!is_expired_prekey_reservation("recipient mailbox is full"));
    }

    #[test]
    fn delivery_receipt_requires_the_expected_ciphertext_hash() {
        let mut receipt = DeliveryStatusRecord {
            envelope_id: "e1".into(),
            status: "delivered".into(),
            delivered_at: Some(100),
            expires_at: 200,
            ciphertext_hash: Some("0xabc".into()),
            recipient_online: true,
        };
        assert_eq!(
            classify_delivery_receipt(&receipt, "0xABC", 150),
            Some("delivered")
        );

        receipt.ciphertext_hash = Some("0xdef".into());
        assert_eq!(
            classify_delivery_receipt(&receipt, "0xabc", 150),
            Some("integrity_error")
        );

        receipt.ciphertext_hash = None;
        assert_eq!(
            classify_delivery_receipt(&receipt, "0xabc", 150),
            Some("integrity_unverified")
        );
        receipt.ciphertext_hash = Some("0xabc".into());
        receipt.delivered_at = None;
        assert_eq!(
            classify_delivery_receipt(&receipt, "0xabc", 150),
            Some("integrity_error")
        );
    }

    #[test]
    fn queued_delivery_distinguishes_presence_and_expiry() {
        let mut receipt = DeliveryStatusRecord {
            envelope_id: "e2".into(),
            status: "queued".into(),
            delivered_at: None,
            expires_at: 200,
            ciphertext_hash: Some("0xabc".into()),
            recipient_online: false,
        };
        assert_eq!(
            classify_delivery_receipt(&receipt, "0xabc", 150),
            Some("waiting_online")
        );
        receipt.recipient_online = true;
        assert_eq!(
            classify_delivery_receipt(&receipt, "0xabc", 150),
            Some("awaiting_delivery")
        );
        assert_eq!(
            classify_delivery_receipt(&receipt, "0xabc", 200),
            Some("awaiting_delivery")
        );
        assert_eq!(
            classify_delivery_receipt(&receipt, "0xabc", 260),
            Some("expired")
        );
    }

    #[test]
    fn local_history_cutoff_is_inclusive() {
        let now_ms = 1_800_000_000_000_i64;
        let cutoff = now_ms - LOCAL_HISTORY_RETENTION_MS;
        let peer = "0x00000000000000000000000000000000000000aa";
        let mut profile = LocalProfile::default();
        profile.messages.push(local_message_fixture(
            "boundary",
            peer,
            cutoff,
            "boundary-body",
        ));
        profile.messages.push(local_message_fixture(
            "expired",
            peer,
            cutoff - 1,
            "expired-body",
        ));

        let (removed, changed) = prune_local_profile(&mut profile, now_ms);
        assert_eq!(removed, 1);
        assert!(changed);
        assert_eq!(profile.messages.len(), 1);
        assert_eq!(profile.messages[0].envelope_id, "boundary");
        assert_eq!(profile.messages[0].body, "boundary-body");
    }

    #[test]
    fn deleted_messages_wipe_body_alias_and_outbox_buffers() {
        let peer = "0x00000000000000000000000000000000000000aa";
        let mut message = local_message_fixture("wipe", peer, 1, "sensitive-body");
        zeroize_local_message(&mut message);
        assert!(message.body.is_empty());
        assert!(message.sender_alias.is_empty());
        assert!(message.outbox_envelope.is_none());
        assert!(message.outbox_prekey_id.is_none());
    }

    #[test]
    fn local_history_cap_removes_the_oldest_message() {
        let now_ms = 1_800_000_000_000_i64;
        let peer = "0x00000000000000000000000000000000000000aa";
        let mut profile = LocalProfile::default();
        for index in 0..=MAX_MESSAGES {
            profile.messages.push(local_message_fixture(
                &format!("cap-{index}"),
                peer,
                now_ms - i64::try_from(index).unwrap() * 1_000,
                "cap-body",
            ));
        }
        let (removed, _) = prune_local_profile(&mut profile, now_ms);
        assert_eq!(removed, 1);
        assert_eq!(profile.messages.len(), MAX_MESSAGES);
        assert!(!profile
            .messages
            .iter()
            .any(|message| message.envelope_id == "cap-500"));
        assert!(profile
            .messages
            .iter()
            .any(|message| message.envelope_id == "cap-0"));
    }

    #[test]
    fn future_sender_timestamp_ages_from_local_ingestion() {
        let now_ms = 1_800_000_000_000_i64;
        let peer = "0x00000000000000000000000000000000000000aa";
        let mut profile = LocalProfile::default();
        profile.messages.push(local_message_fixture(
            "future",
            peer,
            now_ms + 365 * 24 * 60 * 60 * 1_000,
            "future-body",
        ));
        let (first_removed, _) = prune_local_profile(&mut profile, now_ms);
        assert_eq!(first_removed, 0);
        assert_eq!(profile.messages[0].local_ingested_at, Some(now_ms));

        let (later_removed, _) =
            prune_local_profile(&mut profile, now_ms + LOCAL_HISTORY_RETENTION_MS + 1);
        assert_eq!(later_removed, 1);
        assert!(profile.messages.is_empty());
    }

    #[test]
    fn conversation_index_survives_body_pruning_and_stays_bounded() {
        let now_ms = 1_800_000_000_000_i64;
        let peer = "0x00000000000000000000000000000000000000aa";
        let mut profile = LocalProfile::default();
        profile.messages.push(local_message_fixture(
            "old-conversation",
            peer,
            now_ms - LOCAL_HISTORY_RETENTION_MS - 1,
            "old-body",
        ));
        let _ = prune_local_profile(&mut profile, now_ms);
        assert!(profile.messages.is_empty());
        assert_eq!(profile.conversation_wallets, vec![peer.to_string()]);

        let mut capped = LocalProfile::default();
        for index in 1..=(MAX_CONVERSATION_WALLETS + 25) {
            capped.conversation_wallets.push(format!("0x{index:040x}"));
        }
        let _ = prune_local_profile(&mut capped, now_ms);
        assert_eq!(capped.conversation_wallets.len(), MAX_CONVERSATION_WALLETS);
        assert_eq!(
            capped.conversation_wallets[0],
            "0x0000000000000000000000000000000000000001"
        );
    }

    #[test]
    fn exact_tombstone_capacity_expires_and_releases_a_slot() {
        let now_ms = 1_800_000_000_000_i64;
        let expires_at = now_ms / 1_000 + 100;
        let mut profile = LocalProfile::default();
        for index in 0..MAX_RECEIVED_TOMBSTONES {
            assert!(record_received_tombstone(
                &mut profile,
                &format!("tombstone-{index}"),
                &format!("0x{index:064x}"),
                "delivered",
                expires_at,
                now_ms + i64::try_from(index).unwrap(),
            ));
        }
        let oldest_id = profile.received_envelope_tombstones[0].envelope_id.clone();
        assert!(!record_received_tombstone(
            &mut profile,
            "tombstone-over-cap",
            "0xdead",
            "delivered",
            expires_at,
            now_ms + 10_000,
        ));
        assert_eq!(
            profile.received_envelope_tombstones.len(),
            MAX_RECEIVED_TOMBSTONES
        );
        assert!(profile
            .received_envelope_tombstones
            .iter()
            .any(|tombstone| tombstone.envelope_id == oldest_id));

        let expired_at_ms = (expires_at + RELAY_EXPIRY_GRACE_SECONDS) * 1_000;
        assert!(prune_received_tombstones(&mut profile, expired_at_ms));
        assert!(profile.received_envelope_tombstones.is_empty());
        assert!(record_received_tombstone(
            &mut profile,
            "released-slot",
            "0xreleased",
            "rejected",
            expires_at,
            expired_at_ms,
        ));
    }

    #[test]
    fn oversized_legacy_tombstones_preserve_live_records_and_fail_closed() {
        let now_ms = 1_800_000_000_000_i64;
        let expires_at = now_ms / 1_000 + RELAY_ENVELOPE_TTL_SECONDS;
        let mut oversized = LocalProfile::default();
        for index in 0..=MAX_RECEIVED_TOMBSTONES {
            oversized
                .received_envelope_tombstones
                .push(ReceivedEnvelopeTombstone {
                    envelope_id: format!("legacy-tombstone-{index}"),
                    ciphertext_hash: "0xhash".to_string(),
                    outcome: "delivered".to_string(),
                    expires_at,
                    recorded_at: now_ms + i64::try_from(index).unwrap(),
                });
        }
        let oldest_id = oversized.received_envelope_tombstones[0]
            .envelope_id
            .clone();
        let _ = prune_received_tombstones(&mut oversized, now_ms);
        assert_eq!(
            oversized.received_envelope_tombstones.len(),
            MAX_RECEIVED_TOMBSTONES + 1
        );
        assert!(oversized
            .received_envelope_tombstones
            .iter()
            .any(|tombstone| tombstone.envelope_id == oldest_id));
        assert!(!reserve_tombstone_capacity(&mut oversized, now_ms));
        assert!(!record_received_tombstone(
            &mut oversized,
            "new-id",
            "0xnew",
            "rejected",
            expires_at,
            now_ms,
        ));
        assert_eq!(
            oversized.received_envelope_tombstones.len(),
            MAX_RECEIVED_TOMBSTONES + 1
        );
    }

    #[test]
    fn duplicate_tombstones_are_hash_bound_and_rejected_mismatches_do_not_deliver() {
        let mut profile = LocalProfile::default();
        assert!(record_received_tombstone(
            &mut profile,
            "duplicate-id",
            "0xaccepted",
            "delivered",
            1_900_000_000,
            1_800_000_000_000,
        ));
        let tombstone = &profile.received_envelope_tombstones[0];
        assert_eq!(tombstone_ack_outcome(tombstone, "0xACCEPTED"), "delivered");
        assert_eq!(tombstone_ack_outcome(tombstone, "0xother"), "rejected");

        assert!(record_received_tombstone(
            &mut profile,
            "rejected-id",
            "0xrejected",
            "rejected",
            1_900_000_000,
            1_800_000_000_000,
        ));
        let rejected = &profile.received_envelope_tombstones[1];
        assert_eq!(tombstone_ack_outcome(rejected, "0xREJECTED"), "rejected");
    }

    #[test]
    fn full_metadata_capacity_fails_before_ratchet_work_and_ack_reservation() {
        let now_ms = 1_800_000_000_000_i64;
        let expires_at = now_ms / 1_000 + RELAY_ENVELOPE_TTL_SECONDS;
        let mut profile = LocalProfile::default();
        for index in 0..MAX_RECEIVED_TOMBSTONES {
            assert!(record_received_tombstone(
                &mut profile,
                &format!("full-{index}"),
                "0xhash",
                "rejected",
                expires_at,
                now_ms,
            ));
        }
        let account = SecureAccount::new();
        let before = account.serialize_state().expect("ratchet snapshot");
        assert!(!reserve_tombstone_capacity(&mut profile, now_ms));
        assert!(!record_received_tombstone(
            &mut profile,
            "unremembered-new-id",
            "0xnew",
            "rejected",
            expires_at,
            now_ms,
        ));
        assert_eq!(
            account.serialize_state().expect("unchanged ratchet"),
            before
        );
        assert!(!profile
            .received_envelope_tombstones
            .iter()
            .any(|tombstone| tombstone.envelope_id == "unremembered-new-id"));
    }

    #[test]
    fn old_profile_extra_guard_is_ignored_and_not_persisted() {
        let old = json!({
            "version": PROFILE_VERSION,
            "device_id": "99999999-9999-4999-8999-999999999999",
            "self_alias": "legacy",
            "sessions": {},
            "trusted_fingerprints": {},
            "generated_prekey_ids": [],
            "unconfirmed_sessions": [],
            "conversation_wallets": [],
            "received_envelope_tombstones": [],
            "received_envelope_replay_guard": [255, 255, 255],
            "messages": [],
            "account_state": []
        });
        let profile: PersistedProfile = serde_json::from_value(old).expect("legacy profile");
        let current = serde_json::to_value(profile).expect("current profile");
        assert!(current.get("received_envelope_replay_guard").is_none());
    }

    #[test]
    fn refresh_report_and_legacy_message_defaults_remain_serde_compatible() {
        let report: RefreshReport = serde_json::from_value(json!({
            "delivered": 1,
            "pending_senders": [],
            "rejected": 0,
            "discarded_unverified": 0,
            "malformed": 0,
            "authentication_failed": 0,
            "acknowledged": 1,
            "more_pending": false
        }))
        .expect("legacy refresh report");
        assert!(!report.metadata_capacity_full);
        let serialized = serde_json::to_value(report).expect("refresh report JSON");
        assert_eq!(serialized["metadata_capacity_full"], false);
    }

    #[test]
    fn future_sender_timestamp_is_hidden_but_sorted_by_local_ingestion() {
        let now_ms = 1_800_000_000_000_i64;
        let peer = "0x00000000000000000000000000000000000000aa";
        let mut message = local_message_fixture(
            "future-display",
            peer,
            now_ms + SENDER_TIMESTAMP_FUTURE_GRACE_MS + 1,
            "future-body",
        );
        message.outgoing = false;
        message.local_ingested_at = Some(now_ms);
        message.sender_timestamp_valid = false;
        assert_eq!(message.display_sent_at(), None);
        assert_eq!(message.history_sort_timestamp(), now_ms);
        assert_eq!(
            message.created_at,
            now_ms + SENDER_TIMESTAMP_FUTURE_GRACE_MS + 1
        );

        let legacy: LocalChatMessage = serde_json::from_value(json!({
            "envelope_id": "legacy-positive-time",
            "peer_wallet": peer,
            "peer_device_id": "peer-device",
            "sender_wallet": AUTH_TEST_WALLET,
            "sender_alias": "Alice",
            "body": "legacy",
            "created_at": now_ms,
            "outgoing": false,
            "ciphertext_hash": "0xabc",
            "status": "received",
            "anchor_tx": null
        }))
        .expect("legacy message");
        assert_eq!(legacy.display_sent_at(), Some(now_ms));
    }

    #[test]
    fn write_encrypted_browser_profile_fixture_when_requested() {
        let Some(path) = std::env::var_os("NODO_TEST_PROFILE_OUTPUT") else {
            return;
        };
        let path = std::path::PathBuf::from(path);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("fixture parent directory");
        }
        let wallet = "0x0000000000000000000000000000000000000099";
        let peer_a = "0x00000000000000000000000000000000000000aa";
        let peer_b = "0x00000000000000000000000000000000000000bb";
        let now_ms = timestamp_ms();
        let account = SecureAccount::new();
        let mut account_state = account.serialize_state().expect("fixture account state");
        let mut fixture_messages = vec![
            local_message_fixture("fixture-recent-a", peer_a, now_ms - 1_000, "recent-a"),
            local_message_fixture("fixture-recent-b", peer_b, now_ms - 2_000, "recent-b"),
            local_message_fixture(
                "fixture-old",
                peer_a,
                now_ms - LOCAL_HISTORY_RETENTION_MS - 1_000,
                "old-body-retention-test",
            ),
        ];
        for message in &mut fixture_messages {
            message.sender_wallet = wallet.to_string();
        }
        let mut persisted = PersistedProfile {
            version: PROFILE_VERSION,
            device_id: "99999999-9999-4999-8999-999999999999".to_string(),
            self_alias: "fixture-device".to_string(),
            sessions: HashMap::new(),
            trusted_fingerprints: HashMap::new(),
            generated_prekey_ids: BTreeSet::new(),
            unconfirmed_sessions: BTreeSet::new(),
            conversation_wallets: vec![peer_a.to_string(), peer_b.to_string()],
            received_envelope_tombstones: Vec::new(),
            messages: fixture_messages,
            account_state: std::mem::take(&mut account_state),
        };
        let mut plaintext = Zeroizing::new(Vec::new());
        serde_json::to_writer(&mut *plaintext, &persisted).expect("fixture profile JSON");
        persisted.zeroize_sensitive();
        let encrypted = encrypt_private_state(plaintext.as_slice(), "dummy12+password")
            .expect("fixture encrypted state");
        plaintext.zeroize();
        let encoded = serde_json::to_string(&encrypted).expect("fixture encrypted JSON");
        assert!(!encoded.contains("old-body-retention-test"));
        assert!(!encoded.contains("recent-a"));
        std::fs::write(path, encoded).expect("write encrypted fixture");
        account_state.zeroize();
    }
}
