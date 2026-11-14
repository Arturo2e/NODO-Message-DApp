ALTER TABLE relay_challenges
    ADD COLUMN binding_expires_at BIGINT NULL;

UPDATE relay_challenges
SET binding_expires_at = expires_at
WHERE binding_expires_at IS NULL;

ALTER TABLE relay_challenges
    MODIFY COLUMN binding_expires_at BIGINT NOT NULL;

ALTER TABLE relay_one_time_prekeys
    ADD COLUMN claimed_envelope_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NULL,
    ADD COLUMN claim_expires_at BIGINT NULL,
    ADD COLUMN used_by_envelope_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NULL;

CREATE UNIQUE INDEX uq_relay_prekeys_claimed_envelope
    ON relay_one_time_prekeys (wallet_address, device_id, claimed_envelope_id);

CREATE UNIQUE INDEX uq_relay_prekeys_used_envelope
    ON relay_one_time_prekeys (wallet_address, device_id, used_by_envelope_id);

-- Existing claims did not record which envelope consumed the key. Never reuse
-- those keys; the client can publish a fresh batch after this migration.
UPDATE relay_one_time_prekeys
SET claim_expires_at = 9223372036854775807
WHERE claimed_at IS NOT NULL
  AND used_by_envelope_id IS NULL
  AND claim_expires_at IS NULL;
