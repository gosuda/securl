-- name: CreateEnvelope :one
INSERT INTO envelopes (
    storage_key,
    metadata,
    envelope,
    request_hash,
    etag,
    feature_flags,
    expires_at,
    captcha_key_nonce,
    captcha_key_ciphertext
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9
)
RETURNING storage_key, metadata, envelope, request_hash, etag, feature_flags,
          expires_at, captcha_key_nonce, captcha_key_ciphertext, created_at;

-- name: GetEnvelopeByKey :one
SELECT storage_key, metadata, envelope, request_hash, etag, feature_flags,
       expires_at, captcha_key_nonce, captcha_key_ciphertext, created_at
FROM envelopes
WHERE storage_key = $1 AND (expires_at IS NULL OR expires_at > $2);

-- name: GetEnvelopeMetadataByKey :one
SELECT metadata, feature_flags, expires_at
FROM envelopes
WHERE storage_key = $1 AND (expires_at IS NULL OR expires_at > $2);

-- name: ConsumeEnvelope :one
DELETE FROM envelopes
WHERE storage_key = $1 AND (expires_at IS NULL OR expires_at > $2)
RETURNING storage_key, metadata, envelope, request_hash, etag, feature_flags,
          expires_at, captcha_key_nonce, captcha_key_ciphertext, created_at;

-- name: DeleteExpiredEnvelopes :many
WITH expired AS (
    SELECT envelopes.storage_key
    FROM envelopes
    WHERE envelopes.expires_at IS NOT NULL AND envelopes.expires_at <= $1
    ORDER BY envelopes.expires_at
    LIMIT sqlc.arg(batch_size)
)
DELETE FROM envelopes AS target
USING expired
WHERE target.storage_key = expired.storage_key
RETURNING target.storage_key;
