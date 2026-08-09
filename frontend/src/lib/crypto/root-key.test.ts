import { bytesToHex } from '@noble/hashes/utils.js';
import { describe, expect, it, vi } from 'vitest';
import { deriveRootKeySalt } from './protocol';
import { deriveRootLinkKeys } from './root-key';
import { ROOT_KEY_ARGON2D_V2 } from './root-key-profile';

describe('root link key derivation', () => {
  it('uses the fixed 16 MiB, one-pass, single-lane Argon2d profile', () => {
    expect(ROOT_KEY_ARGON2D_V2).toEqual({
      version: 0x13,
      m: 16384,
      t: 1,
      p: 1,
      dkLen: 32
    });
  });

  it('matches the fixed vector without Worker or WebAssembly support', async () => {
    vi.stubGlobal('Worker', undefined);
    vi.stubGlobal('WebAssembly', undefined);
    try {
      const keys = await deriveRootLinkKeys(
        new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7]),
        'BÜCHER.Example.'
      );
      expect(keys.storageKey).toHaveLength(16);
      expect(keys.encryptionKeyMaterial).toHaveLength(32);
      expect(bytesToHex(keys.storageKey)).toBe('5ee8f7ca856e49f3fe13be3c839cd13c');
      expect(bytesToHex(keys.encryptionKeyMaterial)).toBe(
        '57a65d038c8d5f00cf7d3cae380a2ad28c53cdc78b09f0a3ad1f7d7d95f89736'
      );
      keys.storageKey.fill(0);
      keys.encryptionKeyMaterial.fill(0);
    } finally {
      vi.unstubAllGlobals();
    }
  }, 30000);

  it('canonicalizes and domain-separates the Argon2 salt', () => {
    expect(deriveRootKeySalt('BÜCHER.Example.')).toEqual(
      deriveRootKeySalt('xn--bcher-kva.example')
    );
    expect(deriveRootKeySalt('other.example')).not.toEqual(
      deriveRootKeySalt('xn--bcher-kva.example')
    );
  });

  it('rejects non-64-bit IDs before Argon2 work begins', async () => {
    await expect(deriveRootLinkKeys(new Uint8Array(7), 'example.com')).rejects.toThrow(/8 bytes/);
  });
});
