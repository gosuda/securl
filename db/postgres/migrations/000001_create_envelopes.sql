CREATE TABLE IF NOT EXISTS envelopes (
    storage_key BYTEA PRIMARY KEY,
    metadata BYTEA NOT NULL,
    envelope BYTEA NOT NULL,
    request_hash BYTEA NOT NULL,
    etag TEXT NOT NULL,
    feature_flags INTEGER NOT NULL,
    expires_at TIMESTAMPTZ,
    captcha_key_nonce BYTEA,
    captcha_key_ciphertext BYTEA,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT envelopes_storage_key_length CHECK (octet_length(storage_key) = 32),
    CONSTRAINT envelopes_metadata_nonempty CHECK (octet_length(metadata) > 0),
    CONSTRAINT envelopes_envelope_size CHECK (
        octet_length(envelope) > 0 AND octet_length(envelope) <= 16384
    ),
    CONSTRAINT envelopes_request_hash_length CHECK (octet_length(request_hash) = 32),
    CONSTRAINT envelopes_captcha_key_bundle CHECK (
        (captcha_key_nonce IS NULL AND captcha_key_ciphertext IS NULL)
        OR (
            octet_length(captcha_key_nonce) = 12
            AND captcha_key_ciphertext IS NOT NULL
            AND octet_length(captcha_key_ciphertext) > 0
        )
    )
);

CREATE INDEX IF NOT EXISTS envelopes_expires_at_idx ON envelopes (expires_at);
