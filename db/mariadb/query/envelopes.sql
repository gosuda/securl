-- name: CreateEnvelope :execresult
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
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetEnvelopeByKey :one
SELECT storage_key, metadata, envelope, request_hash, etag, feature_flags,
       expires_at, captcha_key_nonce, captcha_key_ciphertext, created_at
FROM envelopes
WHERE storage_key = ? AND (expires_at IS NULL OR expires_at > ?);

-- name: GetEnvelopeForReplay :one
SELECT storage_key, metadata, envelope, request_hash, etag, feature_flags,
       expires_at, captcha_key_nonce, captcha_key_ciphertext, created_at
FROM envelopes
WHERE storage_key = ?;

-- name: GetEnvelopeMetadataByKey :one
SELECT metadata, feature_flags, expires_at
FROM envelopes
WHERE storage_key = ? AND (expires_at IS NULL OR expires_at > ?);

-- name: LockEnvelopeByKey :one
SELECT storage_key, metadata, envelope, request_hash, etag, feature_flags,
       expires_at, captcha_key_nonce, captcha_key_ciphertext, created_at
FROM envelopes
WHERE storage_key = ? AND (expires_at IS NULL OR expires_at > ?)
FOR UPDATE;

-- name: DeleteEnvelopeByKey :execrows
DELETE FROM envelopes
WHERE storage_key = ?;

-- name: DeleteExpiredEnvelopes :execrows
DELETE FROM envelopes
WHERE expires_at IS NOT NULL AND expires_at <= ?
ORDER BY expires_at
LIMIT ?;
