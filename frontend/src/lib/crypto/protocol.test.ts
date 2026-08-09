import { create, fromBinary, toBinary } from '@bufbuild/protobuf';
import { bytesToHex, hexToBytes } from '@noble/ciphers/utils.js';
import { describe, expect, it } from 'vitest';
import {
  CaptchaLayerSchema,
  EnvelopeMetadataSchema,
  EnvelopeSchema,
  PasswordLayerSchema,
  PasswordProfile,
  PayloadSchema,
  type Envelope
} from '../gen/securl/v1/envelope_pb.js';
import {
  PROTOCOL_VERSION,
  IncorrectPasswordError,
  decryptEnvelope,
  deriveFinalKey,
  deriveLinkKeys,
  encryptEnvelope,
  openLayer,
  serializeMetadata,
  sealLayer
} from './protocol';

const textEncoder = new TextEncoder();

function openPayloadUrl(
  envelope: Envelope,
  idBytes: Uint8Array,
  encryptionKeyMaterial: Uint8Array
): string {
  if (!envelope.metadata) throw new Error('Envelope metadata is required.');
  const metadata = envelope.metadata;
  const aad = serializeMetadata(metadata);
  const finalKey = deriveFinalKey(encryptionKeyMaterial, idBytes, metadata.payloadNonce);
  try {
    const payloadBytes = openLayer(finalKey, metadata.payloadNonce, envelope.ciphertext, aad);
    try {
      return fromBinary(PayloadSchema, payloadBytes).url;
    } finally {
      payloadBytes.fill(0);
    }
  } finally {
    finalKey.fill(0);
  }
}

describe('SecURL v2 envelope protocol', () => {
  const idBytes = new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7]);
  const encryptionKeyMaterial = hexToBytes(
    'ce5d43ea7c46baf44ab56b16d455f021db972374f300ab7b312a63c5e9ad94d4'
  );
  const payloadNonce = new Uint8Array(Array.from({ length: 24 }, (_, index) => index));

  it('binds the final key to both ID and payload nonce', () => {
    const finalKey = deriveFinalKey(encryptionKeyMaterial, idBytes, payloadNonce);
    expect(bytesToHex(finalKey)).toBe(
      '39406d8270ed8d5a6d4f5dbd7e0d09fc7f6c4436b5cf97ec367baaedf66ab2d4'
    );

    const changedNonce = payloadNonce.slice();
    changedNonce[23] ^= 1;
    expect(deriveFinalKey(encryptionKeyMaterial, idBytes, changedNonce)).not.toEqual(finalKey);
  });

  it('matches the IETF XChaCha20-Poly1305 known-answer vector', () => {
    const plaintext = hexToBytes(
      '4c616469657320616e642047656e746c656d656e206f662074686520636c6173' +
        '73206f66202739393a204966204920636f756c64206f6666657220796f75206f' +
        '6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73' +
        '637265656e20776f756c642062652069742e'
    );
    const sealed = sealLayer(
      hexToBytes('808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f'),
      hexToBytes('404142434445464748494a4b4c4d4e4f5051525354555657'),
      plaintext,
      hexToBytes('50515253c0c1c2c3c4c5c6c7')
    );

    expect(bytesToHex(sealed)).toBe(
      'bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb' +
        '731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452' +
        '2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9' +
        '21f9664c97637da9768812f615c68b13b52e' +
        'c0875924c1c7987947deafd8780acf49'
    );
  });

  it('encrypts payload, password, and CAPTCHA layers and decrypts in reverse', () => {
    let randomByte = 1;
    const randomBytes = (length: number) => new Uint8Array(length).fill(randomByte++);
    const passwordKey = new Uint8Array(32).fill(0x41);
    const captchaKey = new Uint8Array(32).fill(0x42);
    const envelope = encryptEnvelope('https://example.com/path?x=1', idBytes, encryptionKeyMaterial, {
      ttlSeconds: 604800,
      password: { key: passwordKey, salt: new Uint8Array(16).fill(0x51) },
      captchaKey,
      burnAfterRead: true,
      randomBytes
    });

    expect(envelope.metadata?.featureFlags).toBe(7);
    expect(envelope.metadata?.payloadNonce).toEqual(new Uint8Array(24).fill(1));
    expect(envelope.metadata?.password?.nonce).toEqual(new Uint8Array(24).fill(2));
    expect(envelope.metadata?.captcha?.nonce).toEqual(new Uint8Array(24).fill(3));
    expect(
      decryptEnvelope(envelope, idBytes, encryptionKeyMaterial, { passwordKey, captchaKey })
    ).toBe('https://example.com/path?x=1');
    expect(() => decryptEnvelope(envelope, idBytes, encryptionKeyMaterial, { passwordKey })).toThrow(/CAPTCHA key/);
    expect(() => decryptEnvelope(envelope, idBytes, encryptionKeyMaterial, { captchaKey })).toThrow(/Password key/);
    expect(() =>
      decryptEnvelope(envelope, idBytes, encryptionKeyMaterial, {
        passwordKey: new Uint8Array(32).fill(0x40),
        captchaKey
      })
    ).toThrow(IncorrectPasswordError);
  });

  it('pads URLs with 0-128 zero bytes on 32-byte boundaries', () => {
    const prefix = 'https://example.com/';
    const destination = prefix + 'a'.repeat(32 - textEncoder.encode(prefix).length);
    const cases = [
      [0, 0],
      [64, 32],
      [128, 64],
      [192, 96],
      [255, 128]
    ] as const;

    for (const [choice, expectedPadding] of cases) {
      const envelope = encryptEnvelope(destination, idBytes, encryptionKeyMaterial, {
        ttlSeconds: 3600,
        randomBytes: (length) =>
          length === 1 ? new Uint8Array([choice]) : new Uint8Array(length).fill(0x31)
      });
      const paddedUrl = openPayloadUrl(envelope, idBytes, encryptionKeyMaterial);

      expect(paddedUrl).toBe(destination + '\0'.repeat(expectedPadding));
      expect(textEncoder.encode(paddedUrl).length).toBe(32 + expectedPadding);
      expect(textEncoder.encode(paddedUrl).length % 32).toBe(0);
      expect(decryptEnvelope(envelope, idBytes, encryptionKeyMaterial)).toBe(destination);
    }
  });

  it('never lets the padded URL exceed 4096 bytes', () => {
    const prefix = 'https://example.com/';
    const nearMaximum = prefix + 'a'.repeat(4000 - textEncoder.encode(prefix).length);
    const maximum = prefix + 'a'.repeat(4096 - textEncoder.encode(prefix).length);
    const randomBytes = (length: number) =>
      length === 1 ? new Uint8Array([255]) : new Uint8Array(length).fill(0x32);

    const nearMaximumEnvelope = encryptEnvelope(nearMaximum, idBytes, encryptionKeyMaterial, {
      ttlSeconds: 3600,
      randomBytes
    });
    const maximumEnvelope = encryptEnvelope(maximum, idBytes, encryptionKeyMaterial, {
      ttlSeconds: 3600,
      randomBytes
    });
    const paddedNearMaximum = openPayloadUrl(
      nearMaximumEnvelope,
      idBytes,
      encryptionKeyMaterial
    );
    const paddedMaximum = openPayloadUrl(maximumEnvelope, idBytes, encryptionKeyMaterial);

    expect(textEncoder.encode(paddedNearMaximum)).toHaveLength(4096);
    expect(paddedNearMaximum.slice(nearMaximum.length)).toBe('\0'.repeat(96));
    expect(textEncoder.encode(paddedMaximum)).toHaveLength(4096);
    expect(paddedMaximum).toBe(maximum);
    expect(decryptEnvelope(nearMaximumEnvelope, idBytes, encryptionKeyMaterial)).toBe(nearMaximum);
    expect(decryptEnvelope(maximumEnvelope, idBytes, encryptionKeyMaterial)).toBe(maximum);
    expect(() =>
      encryptEnvelope(`${maximum}a`, idBytes, encryptionKeyMaterial, { ttlSeconds: 3600, randomBytes })
    ).toThrow(/must not exceed 4096 UTF-8 bytes/);
  });

  it('ignores authenticated payload content after the first null byte', () => {
    const destination = 'https://example.com/';
    const metadata = create(EnvelopeMetadataSchema, {
      protocolVersion: PROTOCOL_VERSION,
      ttlSeconds: 3600,
      payloadNonce
    });
    const aad = serializeMetadata(metadata);
    const finalKey = deriveFinalKey(encryptionKeyMaterial, idBytes, payloadNonce);
    const payloadBytes = toBinary(
      PayloadSchema,
      create(PayloadSchema, { url: `${destination}\0ignored` })
    );
    const ciphertext = sealLayer(finalKey, payloadNonce, payloadBytes, aad);
    payloadBytes.fill(0);
    finalKey.fill(0);

    const envelope = create(EnvelopeSchema, { metadata, ciphertext });
    expect(decryptEnvelope(envelope, idBytes, encryptionKeyMaterial)).toBe(destination);
  });

  it('uses a zero TTL sentinel for envelopes that never expire', () => {
    const envelope = encryptEnvelope('https://example.com/forever', idBytes, encryptionKeyMaterial, {
      ttlSeconds: 0,
      randomBytes: (length) => new Uint8Array(length).fill(0x44)
    });
    expect(envelope.metadata?.ttlSeconds).toBe(0);
    expect(decryptEnvelope(envelope, idBytes, encryptionKeyMaterial)).toBe('https://example.com/forever');
  });

  it('fails authentication if metadata AAD is changed', () => {
    const passwordKey = new Uint8Array(32).fill(0x61);
    const captchaKey = new Uint8Array(32).fill(0x62);
    const original = encryptEnvelope('https://example.com/', idBytes, encryptionKeyMaterial, {
      ttlSeconds: 3600,
      password: { key: passwordKey, salt: new Uint8Array(16).fill(0x63) },
      captchaKey,
      randomBytes: (length) => new Uint8Array(length).fill(0x64)
    });
    const metadata = original.metadata!;
    const tamperedMetadata = create(EnvelopeMetadataSchema, {
      protocolVersion: metadata.protocolVersion,
      featureFlags: metadata.featureFlags,
      ttlSeconds: metadata.ttlSeconds + 1,
      payloadNonce: metadata.payloadNonce,
      password: create(PasswordLayerSchema, {
        salt: metadata.password!.salt,
        nonce: metadata.password!.nonce,
        profile: PasswordProfile.ARGON2D_V1
      }),
      captcha: create(CaptchaLayerSchema, { nonce: metadata.captcha!.nonce })
    });
    const tampered = create(EnvelopeSchema, {
      metadata: tamperedMetadata,
      ciphertext: original.ciphertext
    });

    expect(() => decryptEnvelope(tampered, idBytes, encryptionKeyMaterial, { passwordKey, captchaKey })).toThrow();
  });

  it('rejects non-protocol key and nonce lengths', () => {
    expect(() => deriveLinkKeys(new Uint8Array(31), 'example.com')).toThrow(/32 bytes/);
    expect(() => deriveFinalKey(new Uint8Array(31), idBytes, payloadNonce)).toThrow(/32 bytes/);
    expect(() => deriveFinalKey(new Uint8Array(32), idBytes, new Uint8Array(23))).toThrow(/24 bytes/);
  });
});
