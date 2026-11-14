-- Keep only the random envelope UUID after ciphertext/status rows are purged.
-- This prevents UUID reuse without retaining wallet, device, hash, or ciphertext data.
CREATE TABLE relay_envelope_ids (
    envelope_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    PRIMARY KEY (envelope_id)
) ENGINE=InnoDB;

INSERT IGNORE INTO relay_envelope_ids (envelope_id)
SELECT envelope_id FROM relay_envelopes;
