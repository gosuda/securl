import { bytesToHex } from '@noble/hashes/utils.js';
import { describe, expect, it, vi } from 'vitest';
import { deriveRootKeySalt } from './protocol';
import { deriveRootLinkKeys } from './root-key';
import { ROOT_KEY_ARGON2ID_V2 } from './root-key-profile';

describe('root link key derivation', () => {
  it('uses the fixed 32 MiB, two-pass, single-lane Argon2id profile', () => {
    expect(ROOT_KEY_ARGON2ID_V2).toEqual({
      version: 0x13,
      m: 32768,
      t: 2,
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
      expect(bytesToHex(keys.storageKey)).toBe(
        '995a1508c7b49a78894e648fca5ce145dcf901d79e97fa73233b024daeda29cb'
      );
      expect(bytesToHex(keys.encryptionKeyMaterial)).toBe(
        'd8c7bed5807549611a1392290049dc5c1ed933c2e6fd2834356d15f956d26fa7'
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
