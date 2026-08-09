# Cryptography

SecURL protocol version 2 keeps the destination encrypted in the browser. The server receives a derived storage key, authenticated metadata, and ciphertext. The 64-bit fragment ID remains in the URL fragment and is not sent in HTTP requests.

## Link root key

The browser generates an eight-byte random ID and encodes it as an 11-character Base62 fragment. The normalized service domain is lowercase, IDNA-canonical, and has trailing dots removed.

The Argon2d salt is the first 16 bytes of:

```text
SHA3-256("v2-root-key\0" || normalized_service_domain)
```

The root key is derived with this fixed profile:

```text
Argon2d v1.3
password = id_bytes
salt     = root_key_salt
m        = 16384 KiB
t        = 1
p        = 1
output   = 32 bytes
```

The domain and protocol context prevent generic precomputed tables from being reused across domains or protocol namespaces. The mapping remains deterministic within one domain, so a domain-specific exhaustive search is still possible in principle; Argon2d makes each candidate memory-hard rather than increasing the 64-bit ID entropy.

## Storage and encryption subkeys

The root key is separated into independent 32-byte subkeys with HKDF-SHA3-256:

```text
storage_key = HKDF-SHA3-256(
  IKM  = root_key,
  salt = "v2-storage-key\0" || normalized_service_domain,
  info = empty,
  L    = 16
)

encryption_key_material = HKDF-SHA3-256(
  IKM  = root_key,
  salt = "v2-encryption-key",
  info = empty,
  L    = 32
)
```

The 16-byte storage key is Base64URL-encoded without padding for API lookup. The server never needs the fragment ID or root key.

Each envelope has a random 24-byte payload nonce. The final payload key is:

```text
final_key = HKDF-SHA3-256(
  IKM  = encryption_key_material,
  salt = id_bytes || payload_nonce,
  info = empty,
  L    = 32
)
```

## Payload encryption

The canonical destination URL is serialized in the protobuf `Payload` message. Zero padding is appended after the URL with these rules:

- URL plus padding never exceeds 4096 UTF-8 bytes.
- Padding is between 0 and 128 NUL bytes.
- Candidate padding lengths align the padded URL length to a 32-byte boundary when space permits.
- Decryption ignores the first NUL byte and everything after it.

The payload is encrypted with XChaCha20-Poly1305:

```text
ciphertext_0 = XChaCha20-Poly1305(
  key   = final_key,
  nonce = payload_nonce,
  data  = protobuf_payload,
  AAD   = canonical_envelope_metadata
)
```

The authenticated metadata contains protocol version 2, feature flags, TTL, the payload nonce, and the metadata required by optional password and CAPTCHA layers. Any metadata modification invalidates the AEAD tag.

## Password layer

Password protection uses a random 16-byte salt and Argon2d v1.3:

```text
m = 16384 KiB
t = 1
p = 1
output = 32 bytes
```

The derived password key encrypts the payload ciphertext with a separate random 24-byte XChaCha20-Poly1305 nonce and the same authenticated metadata:

```text
ciphertext_1 = XChaCha20-Poly1305(password_key, password_nonce, ciphertext_0, AAD)
```

The per-link password salt prevents password precomputation from being reused across links. Password strength still determines resistance to dictionary attacks.

## CAPTCHA layer

CAPTCHA protection uses an independent random 32-byte client key and another random 24-byte XChaCha20-Poly1305 nonce:

```text
ciphertext_2 = XChaCha20-Poly1305(captcha_key, captcha_nonce, ciphertext_1, AAD)
```

The server wraps the CAPTCHA key with AES-256-GCM under `SECURL_CAPTCHA_WRAP_KEY`. The wrapping AAD is the storage key followed by the big-endian protocol version. After successful protected access, the server unwraps and returns the CAPTCHA key to the browser.

CAPTCHA is an access-control layer, not a confidentiality boundary against the server operator that controls the wrapping key.

## Decryption order

The browser performs the inverse operations:

1. Decode the 64-bit fragment ID.
2. Derive the Argon2d root key and HKDF subkeys.
3. Fetch and validate protocol version 2 metadata.
4. Obtain the CAPTCHA key when required.
5. Derive the password key when required.
6. Remove the CAPTCHA layer.
7. Remove the password layer.
8. Derive the final payload key and decrypt the payload.
9. Remove NUL padding and validate the destination URL again.

Temporary root, encryption, password, CAPTCHA, payload, and plaintext byte arrays are zero-filled at their final use sites where the runtime exposes mutable storage.
