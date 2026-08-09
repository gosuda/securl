import { bytesToHex } from '@noble/hashes/utils.js';
import { describe, expect, it, vi } from 'vitest';
import { derivePasswordKey } from './password';
import { derivePasswordKeyDirect } from './password-derivation';
import { ARGON2D_V1 } from './password-profile';

describe('ARGON2D_V1 password derivation', () => {
  it('matches the fixed vector without Worker or WebAssembly support', async () => {
    expect(ARGON2D_V1).toEqual({ version: 0x13, m: 16384, t: 1, p: 1, dkLen: 32 });
    vi.stubGlobal('Worker', undefined);
    vi.stubGlobal('WebAssembly', undefined);
    try {
      const key = await derivePasswordKey(
        'password',
        new Uint8Array(Array.from({ length: 16 }, (_, index) => index))
      );
      expect(bytesToHex(key)).toBe(
        'b1dab073f1369bdbd26aad51729835d26d60e553f2f6b1dc1710265a9ac53ae5'
      );
      key.fill(0);
    } finally {
      vi.unstubAllGlobals();
    }
  }, 30000);

  it('validates the original UTF-8 bytes without trimming', async () => {
    await expect(derivePasswordKeyDirect('', new Uint8Array(16))).rejects.toThrow(/1 and 1024/);
    await expect(derivePasswordKeyDirect(' '.repeat(1025), new Uint8Array(16))).rejects.toThrow(
      /1 and 1024/
    );
    await expect(derivePasswordKeyDirect('valid', new Uint8Array(15))).rejects.toThrow(/16 bytes/);
  });
});
