import { create, fromBinary, toBinary } from '@bufbuild/protobuf';
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha3_256 } from '@noble/hashes/sha3.js';
import { normalizeServiceDomain } from '../security/domain';
import { MAX_URL_BYTES } from '../security/url';
import {
  CaptchaLayerSchema,
  EnvelopeMetadataSchema,
  EnvelopeSchema,
  FeatureFlag,
  PasswordLayerSchema,
  PasswordProfile,
  PayloadSchema,
  type Envelope,
  type EnvelopeMetadata
} from '../gen/securl/v1/envelope_pb.js';

const textEncoder = new TextEncoder();
const EMPTY_INFO = new Uint8Array();
const STORAGE_KEY_SALT_PREFIX = textEncoder.encode('v1-storage-key\0');
const ENCRYPTION_KEY_SALT = textEncoder.encode('v1-encryption-key');
const KNOWN_FEATURE_FLAGS =
  FeatureFlag.CAPTCHA | FeatureFlag.PASSWORD | FeatureFlag.BURN_AFTER_READ;

export const KEY_LENGTH = 32;
export const PAYLOAD_NONCE_LENGTH = 24;
export const PASSWORD_SALT_LENGTH = 16;
const URL_PADDING_ALIGNMENT = 32;
const MAX_URL_PADDING_LENGTH = 128;
const NULL_BYTE = '\0';

export interface PasswordEncryptionLayer {
  key: Uint8Array;
  salt: Uint8Array;
}

export interface EncryptEnvelopeOptions {
  ttlSeconds: number;
  password?: PasswordEncryptionLayer;
  captchaKey?: Uint8Array;
  burnAfterRead?: boolean;
  randomBytes?: (length: number) => Uint8Array;
}

export interface DecryptEnvelopeOptions {
  passwordKey?: Uint8Array;
  captchaKey?: Uint8Array;
}

function requireIdBytes(idBytes: Uint8Array): void {
  if (idBytes.length !== 8) {
    throw new Error('ID must be exactly 8 bytes.');
  }
}

function requireKey(key: Uint8Array, name: string): void {
  if (key.length !== KEY_LENGTH) {
    throw new Error(`${name} must be exactly 32 bytes.`);
  }
}

function takeRandomBytes(length: number, source?: (length: number) => Uint8Array): Uint8Array {
  const bytes = source ? source(length) : crypto.getRandomValues(new Uint8Array(length));
  if (bytes.length !== length) {
    throw new Error(`Random source returned ${bytes.length} bytes; expected ${length}.`);
  }
  return bytes.slice();
}

function padDestinationUrl(
  destinationUrl: string,
  source?: (length: number) => Uint8Array
): string {
  const destinationBytes = textEncoder.encode(destinationUrl);
  const destinationLength = destinationBytes.length;
  destinationBytes.fill(0);
  if (destinationLength > MAX_URL_BYTES) {
    throw new Error(`Destination URL must not exceed ${MAX_URL_BYTES} UTF-8 bytes.`);
  }

  const alignmentPadding =
    (URL_PADDING_ALIGNMENT - (destinationLength % URL_PADDING_ALIGNMENT)) %
    URL_PADDING_ALIGNMENT;
  const availablePadding = Math.min(
    MAX_URL_PADDING_LENGTH,
    MAX_URL_BYTES - destinationLength
  );
  const candidateCount =
    Math.floor((availablePadding - alignmentPadding) / URL_PADDING_ALIGNMENT) + 1;
  if (candidateCount === 1) {
    return alignmentPadding === 0
      ? destinationUrl
      : destinationUrl + NULL_BYTE.repeat(alignmentPadding);
  }

  const randomChoice = takeRandomBytes(1, source);
  try {
    // Choose among only the padding lengths that align the padded URL byte length.
    const paddingLength =
      alignmentPadding +
      Math.floor((randomChoice[0] * candidateCount) / 256) * URL_PADDING_ALIGNMENT;
    return paddingLength === 0
      ? destinationUrl
      : destinationUrl + NULL_BYTE.repeat(paddingLength);
  } finally {
    randomChoice.fill(0);
  }
}

export function deriveStorageKey(idBytes: Uint8Array, serviceDomain: string): Uint8Array {
  requireIdBytes(idBytes);
  const domainBytes = textEncoder.encode(normalizeServiceDomain(serviceDomain));
  const salt = new Uint8Array(STORAGE_KEY_SALT_PREFIX.length + domainBytes.length);
  salt.set(STORAGE_KEY_SALT_PREFIX);
  salt.set(domainBytes, STORAGE_KEY_SALT_PREFIX.length);
  return hkdf(sha3_256, idBytes, salt, EMPTY_INFO, KEY_LENGTH);
}

export function deriveEncryptionKeyMaterial(idBytes: Uint8Array): Uint8Array {
  requireIdBytes(idBytes);
  return hkdf(sha3_256, idBytes, ENCRYPTION_KEY_SALT, EMPTY_INFO, KEY_LENGTH);
}

export function deriveFinalKey(
  encryptionKeyMaterial: Uint8Array,
  idBytes: Uint8Array,
  payloadNonce: Uint8Array
): Uint8Array {
  requireKey(encryptionKeyMaterial, 'Encryption key material');
  requireIdBytes(idBytes);
  if (payloadNonce.length !== PAYLOAD_NONCE_LENGTH) {
    throw new Error('Payload nonce must be exactly 24 bytes.');
  }

  const salt = new Uint8Array(idBytes.length + payloadNonce.length);
  salt.set(idBytes);
  salt.set(payloadNonce, idBytes.length);
  return hkdf(sha3_256, encryptionKeyMaterial, salt, EMPTY_INFO, KEY_LENGTH);
}

export function encodeStorageKey(storageKey: Uint8Array): string {
  requireKey(storageKey, 'Storage key');
  let binary = '';
  for (const byte of storageKey) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
}

export function validateEnvelopeMetadata(metadata: EnvelopeMetadata): void {
  if (metadata.protocolVersion !== 1) {
    throw new Error('Unsupported protocol version.');
  }
  if ((metadata.featureFlags & ~KNOWN_FEATURE_FLAGS) !== 0) {
    throw new Error('Envelope contains unknown feature flags.');
  }
  if (!Number.isInteger(metadata.ttlSeconds) || metadata.ttlSeconds < 0) {
    throw new Error('Envelope TTL must be a non-negative integer. Zero means no expiration.');
  }
  if (metadata.payloadNonce.length !== PAYLOAD_NONCE_LENGTH) {
    throw new Error('Payload nonce must be exactly 24 bytes.');
  }

  const passwordEnabled = (metadata.featureFlags & FeatureFlag.PASSWORD) !== 0;
  if (passwordEnabled !== (metadata.password !== undefined)) {
    throw new Error('Password metadata does not match feature flags.');
  }
  if (
    metadata.password &&
    (metadata.password.salt.length !== PASSWORD_SALT_LENGTH ||
      metadata.password.nonce.length !== PAYLOAD_NONCE_LENGTH ||
      metadata.password.profile !== PasswordProfile.ARGON2ID_V1)
  ) {
    throw new Error('Invalid password layer metadata.');
  }

  const captchaEnabled = (metadata.featureFlags & FeatureFlag.CAPTCHA) !== 0;
  if (captchaEnabled !== (metadata.captcha !== undefined)) {
    throw new Error('CAPTCHA metadata does not match feature flags.');
  }
  if (metadata.captcha && metadata.captcha.nonce.length !== PAYLOAD_NONCE_LENGTH) {
    throw new Error('Invalid CAPTCHA layer metadata.');
  }
}

export function serializeMetadata(metadata: EnvelopeMetadata): Uint8Array {
  validateEnvelopeMetadata(metadata);
  return toBinary(EnvelopeMetadataSchema, metadata, { writeUnknownFields: false });
}

export function sealLayer(
  key: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array,
  aad: Uint8Array
): Uint8Array {
  requireKey(key, 'Encryption key');
  if (nonce.length !== PAYLOAD_NONCE_LENGTH) {
    throw new Error('Encryption nonce must be exactly 24 bytes.');
  }
  return xchacha20poly1305(key, nonce, aad).encrypt(plaintext);
}

export function openLayer(
  key: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
  aad: Uint8Array
): Uint8Array {
  requireKey(key, 'Decryption key');
  if (nonce.length !== PAYLOAD_NONCE_LENGTH) {
    throw new Error('Decryption nonce must be exactly 24 bytes.');
  }
  return xchacha20poly1305(key, nonce, aad).decrypt(ciphertext);
}

export function encryptEnvelope(
  destinationUrl: string,
  idBytes: Uint8Array,
  options: EncryptEnvelopeOptions
): Envelope {
  requireIdBytes(idBytes);
  if (!Number.isInteger(options.ttlSeconds) || options.ttlSeconds < 0) {
    throw new Error('TTL must be a non-negative integer. Zero means no expiration.');
  }
  if (options.password) {
    requireKey(options.password.key, 'Password key');
    if (options.password.salt.length !== PASSWORD_SALT_LENGTH) {
      throw new Error('Password salt must be exactly 16 bytes.');
    }
  }
  if (options.captchaKey) {
    requireKey(options.captchaKey, 'CAPTCHA key');
  }

  let featureFlags = 0;
  if (options.captchaKey) featureFlags |= FeatureFlag.CAPTCHA;
  if (options.password) featureFlags |= FeatureFlag.PASSWORD;
  if (options.burnAfterRead) featureFlags |= FeatureFlag.BURN_AFTER_READ;

  const payloadNonce = takeRandomBytes(PAYLOAD_NONCE_LENGTH, options.randomBytes);
  const passwordNonce = options.password
    ? takeRandomBytes(PAYLOAD_NONCE_LENGTH, options.randomBytes)
    : undefined;
  const captchaNonce = options.captchaKey
    ? takeRandomBytes(PAYLOAD_NONCE_LENGTH, options.randomBytes)
    : undefined;
  const metadata = create(EnvelopeMetadataSchema, {
    protocolVersion: 1,
    featureFlags,
    ttlSeconds: options.ttlSeconds,
    payloadNonce,
    password: options.password
      ? create(PasswordLayerSchema, {
          salt: options.password.salt.slice(),
          nonce: passwordNonce,
          profile: PasswordProfile.ARGON2ID_V1
        })
      : undefined,
    captcha: options.captchaKey
      ? create(CaptchaLayerSchema, { nonce: captchaNonce })
      : undefined
  });
  const aad = serializeMetadata(metadata);
  const paddedDestinationUrl = padDestinationUrl(destinationUrl, options.randomBytes);
  const payloadBytes = toBinary(
    PayloadSchema,
    create(PayloadSchema, { url: paddedDestinationUrl }),
    { writeUnknownFields: false }
  );
  const keyMaterial = deriveEncryptionKeyMaterial(idBytes);
  const finalKey = deriveFinalKey(keyMaterial, idBytes, payloadNonce);
  keyMaterial.fill(0);

  let ciphertext = sealLayer(finalKey, payloadNonce, payloadBytes, aad);
  payloadBytes.fill(0);
  finalKey.fill(0);
  if (options.password && passwordNonce) {
    const next = sealLayer(options.password.key, passwordNonce, ciphertext, aad);
    ciphertext.fill(0);
    ciphertext = next;
  }
  if (options.captchaKey && captchaNonce) {
    const next = sealLayer(options.captchaKey, captchaNonce, ciphertext, aad);
    ciphertext.fill(0);
    ciphertext = next;
  }

  return create(EnvelopeSchema, { metadata, ciphertext });
}

export function decryptEnvelope(
  envelope: Envelope,
  idBytes: Uint8Array,
  options: DecryptEnvelopeOptions = {}
): string {
  requireIdBytes(idBytes);
  if (!envelope.metadata || envelope.ciphertext.length === 0) {
    throw new Error('Envelope is missing required data.');
  }
  const metadata = envelope.metadata;
  const aad = serializeMetadata(metadata);
  const passwordEnabled = (metadata.featureFlags & FeatureFlag.PASSWORD) !== 0;
  const captchaEnabled = (metadata.featureFlags & FeatureFlag.CAPTCHA) !== 0;
  if (passwordEnabled && !options.passwordKey) {
    throw new Error('Password key is required.');
  }
  if (captchaEnabled && !options.captchaKey) {
    throw new Error('CAPTCHA key is required.');
  }
  if (options.passwordKey) requireKey(options.passwordKey, 'Password key');
  if (options.captchaKey) requireKey(options.captchaKey, 'CAPTCHA key');

  let plaintext: Uint8Array<ArrayBufferLike> = envelope.ciphertext.slice();
  const keyMaterial = deriveEncryptionKeyMaterial(idBytes);
  const finalKey = deriveFinalKey(keyMaterial, idBytes, metadata.payloadNonce);
  keyMaterial.fill(0);
  try {
    if (captchaEnabled && metadata.captcha && options.captchaKey) {
      const next = openLayer(options.captchaKey, metadata.captcha.nonce, plaintext, aad);
      plaintext.fill(0);
      plaintext = next;
    }
    if (passwordEnabled && metadata.password && options.passwordKey) {
      const next = openLayer(options.passwordKey, metadata.password.nonce, plaintext, aad);
      plaintext.fill(0);
      plaintext = next;
    }
    const payloadBytes = openLayer(finalKey, metadata.payloadNonce, plaintext, aad);
    plaintext.fill(0);
    plaintext = payloadBytes;
    const paddedUrl = fromBinary(PayloadSchema, payloadBytes).url;
    const paddingStart = paddedUrl.indexOf(NULL_BYTE);
    return paddingStart === -1 ? paddedUrl : paddedUrl.slice(0, paddingStart);
  } finally {
    plaintext.fill(0);
    finalKey.fill(0);
  }
}
