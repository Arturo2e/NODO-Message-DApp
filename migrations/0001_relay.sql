-- NODO relay schema. This migration is additive and stores public key material plus ciphertext only.
CREATE TABLE IF NOT EXISTS relay_challenges (
    challenge_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    wallet_address CHAR(42) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    device_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    identity_key_hash BINARY(32) NOT NULL,
    nonce_hash BINARY(32) NOT NULL,
    expires_at BIGINT NOT NULL,
    created_at BIGINT NOT NULL,
    consumed_at BIGINT NULL,
    PRIMARY KEY (challenge_id),
    KEY idx_relay_challenges_expiry (expires_at),
    KEY idx_relay_challenges_subject (wallet_address, device_id)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS relay_sessions (
    token_hash BINARY(32) NOT NULL,
    wallet_address CHAR(42) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    device_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    identity_key_hash BINARY(32) NOT NULL,
    expires_at BIGINT NOT NULL,
    created_at BIGINT NOT NULL,
    revoked_at BIGINT NULL,
    PRIMARY KEY (token_hash),
    KEY idx_relay_sessions_expiry (expires_at),
    KEY idx_relay_sessions_subject (wallet_address, device_id)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS relay_devices (
    wallet_address CHAR(42) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    device_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    identity_key_hash BINARY(32) NOT NULL,
    binding_nonce VARCHAR(256) NOT NULL,
    binding_expires_at BIGINT NOT NULL,
    binding_signature VARCHAR(132) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    identity_public_key VARBINARY(256) NOT NULL,
    signed_prekey_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    signed_prekey_public_key VARBINARY(256) NOT NULL,
    signed_prekey_signature VARBINARY(256) NOT NULL,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    PRIMARY KEY (wallet_address, device_id),
    KEY idx_relay_devices_wallet (wallet_address),
    KEY idx_relay_devices_identity_hash (identity_key_hash)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS relay_one_time_prekeys (
    wallet_address CHAR(42) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    device_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    key_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    public_key VARBINARY(256) NOT NULL,
    signature VARBINARY(256) NOT NULL,
    created_at BIGINT NOT NULL,
    claimed_at BIGINT NULL,
    claimed_by_wallet CHAR(42) CHARACTER SET ascii COLLATE ascii_bin NULL,
    claimed_by_device CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NULL,
    PRIMARY KEY (wallet_address, device_id, key_id),
    KEY idx_relay_prekeys_available (wallet_address, device_id, claimed_at, created_at),
    CONSTRAINT fk_relay_prekeys_device FOREIGN KEY (wallet_address, device_id)
        REFERENCES relay_devices (wallet_address, device_id)
        ON DELETE RESTRICT ON UPDATE CASCADE
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS relay_envelopes (
    envelope_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    sender_wallet CHAR(42) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    sender_device_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    recipient_wallet CHAR(42) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    recipient_device_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    prekey_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NULL,
    ciphertext MEDIUMBLOB NOT NULL,
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    delivered_at BIGINT NULL,
    PRIMARY KEY (envelope_id),
    KEY idx_relay_envelopes_inbox (recipient_wallet, recipient_device_id, delivered_at, created_at),
    KEY idx_relay_envelopes_expiry (expires_at),
    KEY idx_relay_envelopes_sender (sender_wallet, sender_device_id, created_at)
) ENGINE=InnoDB;
