import { bytesToHex } from '@noble/hashes/utils.js';
import { describe, expect, it } from 'vitest';
import { ARGON2ID_V1 } from './password-profile';
import { derivePasswordKey } from './password.worker';

describe('ARGON2ID_V1 password derivation', () => {
  it('uses the fixed 64 MiB, three-pass, single-lane profile', async () => {
    expect(ARGON2ID_V1).toEqual({ version: 0x13, m: 65536, t: 3, p: 1, dkLen: 32 });
    const key = await derivePasswordKey(
      'password',
      new Uint8Array(Array.from({ length: 16 }, (_, index) => index))
    );
    expect(bytesToHex(key)).toBe(
      'def6fd068289b9a0cf1114f8e978a2c4dab6faef377d895b9c2d59fc93fc5653'
    );
    key.fill(0);
  }, 30000);

  it('validates the original UTF-8 bytes without trimming', async () => {
    await expect(derivePasswordKey('', new Uint8Array(16))).rejects.toThrow(/1 and 1024/);
    await expect(derivePasswordKey(' '.repeat(1025), new Uint8Array(16))).rejects.toThrow(
      /1 and 1024/
    );
    await expect(derivePasswordKey('valid', new Uint8Array(15))).rejects.toThrow(/16 bytes/);
  });
});
