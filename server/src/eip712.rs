use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use sha3::{Digest, Keccak256};
use thiserror::Error;

const DOMAIN_TYPE: &[u8] = b"EIP712Domain(string name,string version,uint256 chainId)";
const BINDING_TYPE: &[u8] = b"IdentityKeyBinding(address wallet,string deviceId,bytes32 identityKeyHash,string nonce,uint64 expiresAt)";
const DOMAIN_NAME: &[u8] = b"NODO Secure Messaging";
const DOMAIN_VERSION: &[u8] = b"1";
const CHAIN_ID: u64 = 11_155_111;

#[derive(Debug, Error)]
pub enum VerificationError {
    #[error("signature must be a 65-byte 0x-prefixed hex value")]
    InvalidSignatureEncoding,
    #[error("signature recovery id must be 0, 1, 27, or 28")]
    InvalidRecoveryId,
    #[error("signature has a non-canonical high-s value")]
    HighS,
    #[error("signature recovery failed")]
    RecoveryFailed,
    #[error("wallet address must be a 20-byte 0x-prefixed hex value")]
    InvalidWallet,
}

fn keccak(input: &[u8]) -> [u8; 32] {
    let digest = Keccak256::digest(input);
    let mut output = [0_u8; 32];
    output.copy_from_slice(&digest);
    output
}

fn uint256(value: u64) -> [u8; 32] {
    let mut output = [0_u8; 32];
    output[24..].copy_from_slice(&value.to_be_bytes());
    output
}

fn parse_wallet(wallet: &str) -> Result<[u8; 20], VerificationError> {
    let raw = wallet
        .strip_prefix("0x")
        .or_else(|| wallet.strip_prefix("0X"))
        .ok_or(VerificationError::InvalidWallet)?;
    if raw.len() != 40 || !raw.as_bytes().iter().all(u8::is_ascii_hexdigit) {
        return Err(VerificationError::InvalidWallet);
    }
    let decoded = hex::decode(raw).map_err(|_| VerificationError::InvalidWallet)?;
    let mut output = [0_u8; 20];
    output.copy_from_slice(&decoded);
    Ok(output)
}

fn domain_separator() -> [u8; 32] {
    let type_hash = keccak(DOMAIN_TYPE);
    let name_hash = keccak(DOMAIN_NAME);
    let version_hash = keccak(DOMAIN_VERSION);
    let chain_id = uint256(CHAIN_ID);
    let mut encoded = Vec::with_capacity(128);
    encoded.extend_from_slice(&type_hash);
    encoded.extend_from_slice(&name_hash);
    encoded.extend_from_slice(&version_hash);
    encoded.extend_from_slice(&chain_id);
    keccak(&encoded)
}

/// Calculate the EIP-712 digest for the exact wallet binding requested by the app.
/// The field order and primitive widths intentionally match the public typed-data JSON.
pub fn identity_key_binding_digest(
    wallet: &str,
    device_id: &str,
    identity_key_hash: &[u8; 32],
    nonce: &str,
    expires_at: u64,
) -> Result<[u8; 32], VerificationError> {
    let wallet = parse_wallet(wallet)?;
    let type_hash = keccak(BINDING_TYPE);
    let device_hash = keccak(device_id.as_bytes());
    let nonce_hash = keccak(nonce.as_bytes());
    let mut encoded = Vec::with_capacity(32 * 6);
    encoded.extend_from_slice(&type_hash);
    encoded.extend_from_slice(&[0_u8; 12]);
    encoded.extend_from_slice(&wallet);
    encoded.extend_from_slice(&device_hash);
    encoded.extend_from_slice(identity_key_hash);
    encoded.extend_from_slice(&nonce_hash);
    encoded.extend_from_slice(&uint256(expires_at));
    let struct_hash = keccak(&encoded);

    let mut digest_input = Vec::with_capacity(66);
    digest_input.extend_from_slice(b"\x19\x01");
    digest_input.extend_from_slice(&domain_separator());
    digest_input.extend_from_slice(&struct_hash);
    Ok(keccak(&digest_input))
}

/// Recover and normalize the Ethereum address that signed the binding.
pub fn recover_wallet(
    wallet: &str,
    device_id: &str,
    identity_key_hash: &[u8; 32],
    nonce: &str,
    expires_at: u64,
    signature_hex: &str,
) -> Result<String, VerificationError> {
    let signature_bytes = signature_hex
        .strip_prefix("0x")
        .or_else(|| signature_hex.strip_prefix("0X"))
        .ok_or(VerificationError::InvalidSignatureEncoding)
        .and_then(|raw| {
            if raw.len() != 130 {
                return Err(VerificationError::InvalidSignatureEncoding);
            }
            hex::decode(raw).map_err(|_| VerificationError::InvalidSignatureEncoding)
        })?;
    let recovery_byte = match signature_bytes[64] {
        0 | 1 => signature_bytes[64],
        27 | 28 => signature_bytes[64] - 27,
        _ => return Err(VerificationError::InvalidRecoveryId),
    };
    let signature = Signature::from_slice(&signature_bytes[..64])
        .map_err(|_| VerificationError::InvalidSignatureEncoding)?;
    if signature.normalize_s().is_some() {
        return Err(VerificationError::HighS);
    }
    let recovery_id =
        RecoveryId::try_from(recovery_byte).map_err(|_| VerificationError::InvalidRecoveryId)?;
    let digest =
        identity_key_binding_digest(wallet, device_id, identity_key_hash, nonce, expires_at)?;
    let verifying_key = VerifyingKey::recover_from_prehash(&digest, &signature, recovery_id)
        .map_err(|_| VerificationError::RecoveryFailed)?;
    let public_key = verifying_key.to_encoded_point(false);
    let public_key = public_key.as_bytes();
    let address_hash = keccak(&public_key[1..]);
    Ok(format!("0x{}", hex::encode(&address_hash[12..])))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fixed_identity_binding_vector_recovers_known_wallet() {
        let wallet = "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf";
        let device_id = "11111111-1111-4111-8111-111111111111";
        let identity_key_hash = [0x11_u8; 32];
        let nonce = "test-nonce-7f6d0b";
        let expires_at = 1_735_689_600_u64;
        let digest =
            identity_key_binding_digest(wallet, device_id, &identity_key_hash, nonce, expires_at)
                .expect("vector digest");
        assert_eq!(
            hex::encode(digest),
            "1a497f342914c4ca2bba77ee43e535efff57f4efd852518f3a1fd6c24737a2c3"
        );
        let signature_hex = "0x7b44f3baed02fa407aa1e031c1bcc5f46bbbfa5f39e4f36d4f0a394d41bb0cc00f07bbe11404cb8dcaa3ab7701fa545b95cea0080887816aa08c29113318bf1f1c";
        assert_eq!(
            recover_wallet(
                wallet,
                device_id,
                &identity_key_hash,
                nonce,
                expires_at,
                &signature_hex,
            )
            .expect("recovered wallet"),
            wallet.to_ascii_lowercase()
        );
    }
}
