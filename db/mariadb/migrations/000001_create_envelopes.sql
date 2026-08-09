CREATE TABLE IF NOT EXISTS envelopes (
    storage_key BINARY(16) NOT NULL PRIMARY KEY,
    metadata LONGBLOB NOT NULL,
    envelope LONGBLOB NOT NULL,
    request_hash BINARY(32) NOT NULL,
    etag VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    feature_flags INT UNSIGNED NOT NULL,
    expires_at DATETIME(6) NULL,
    captcha_key_nonce VARBINARY(12) NOT NULL,
    captcha_key_ciphertext LONGBLOB NOT NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    INDEX envelopes_expires_at_idx (expires_at),
    CONSTRAINT envelopes_metadata_nonempty CHECK (OCTET_LENGTH(metadata) > 0),
    CONSTRAINT envelopes_envelope_size CHECK (
        OCTET_LENGTH(envelope) > 0 AND OCTET_LENGTH(envelope) <= 16384
    ),
    CONSTRAINT envelopes_captcha_key_bundle CHECK (
        (OCTET_LENGTH(captcha_key_nonce) = 0 AND OCTET_LENGTH(captcha_key_ciphertext) = 0)
        OR (
            OCTET_LENGTH(captcha_key_nonce) = 12
            AND OCTET_LENGTH(captcha_key_ciphertext) > 0
        )
    )
) ENGINE=InnoDB DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_bin;
