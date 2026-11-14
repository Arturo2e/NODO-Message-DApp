-- Presence is an approximate, short-lived signal for an unlocked device.
ALTER TABLE relay_devices
    ADD COLUMN presence_until BIGINT NOT NULL DEFAULT 0;

-- Keep only opaque ciphertext while queued; retain a Keccak commitment and a
-- minimal delivery result after the ciphertext is acknowledged and cleared.
ALTER TABLE relay_envelopes
    ADD COLUMN ciphertext_hash BINARY(32) NULL,
    ADD COLUMN delivery_status VARCHAR(16) NOT NULL DEFAULT 'queued';

UPDATE relay_envelopes
SET delivery_status = 'delivered'
WHERE delivered_at IS NOT NULL;
