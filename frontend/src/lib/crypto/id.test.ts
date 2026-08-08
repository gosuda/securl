import { describe, expect, it } from 'vitest';
import {
  BASE62_ALPHABET,
  decodeId,
  encodeId,
  generateIdBytes,
  parseFragment
} from './id';

describe('fragment identifiers', () => {
  it('round-trips unsigned little-endian 64-bit values through fixed Base62', () => {
    const vectors = [
      new Uint8Array(8),
      new Uint8Array([1, 0, 0, 0, 0, 0, 0, 0]),
      new Uint8Array([0, 1, 0, 0, 0, 0, 0, 0]),
      new Uint8Array(8).fill(0xff)
    ];

    for (const vector of vectors) {
      const encoded = encodeId(vector);
      expect(encoded).toHaveLength(11);
      expect([...encoded].every((character) => BASE62_ALPHABET.includes(character))).toBe(true);
      expect(decodeId(encoded)).toEqual(vector);
    }

    expect(encodeId(vectors[0])).toBe('00000000000');
    expect(encodeId(vectors[1])).toBe('00000000001');
    expect(encodeId(vectors[2])).toBe('00000000048');
  });

  it('rejects non-canonical, overflowing, and malformed encodings', () => {
    expect(() => decodeId('zzzzzzzzzzz')).toThrow(/64-bit/);
    expect(() => decodeId('0000000000')).toThrow(/11/);
    expect(() => decodeId('0000000000-')).toThrow(/Base62/);
    expect(() => parseFragment('#%300000000000')).toThrow(/Invalid/);
    expect(() => parseFragment('#00000000000/')).toThrow(/Invalid/);
    expect(() => parseFragment('#00000000000#')).toThrow(/Invalid/);
    expect(() => parseFragment('#00000000000 ')).toThrow(/Invalid/);
  });

  it('accepts only an exact fragment and returns eight random bytes', () => {
    expect(parseFragment('#00000000001')).toEqual(new Uint8Array([1, 0, 0, 0, 0, 0, 0, 0]));
    expect(generateIdBytes()).toHaveLength(8);
  });
});
