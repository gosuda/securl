import { argon2dAsync } from '@noble/hashes/argon2.js';
import { deriveLinkKeys, deriveRootKeySalt, type LinkKeys } from './protocol';
import {
  ROOT_KEY_ARGON2D_V2,
  ROOT_KEY_DERIVATION_UNAVAILABLE
} from './root-key-profile';

export async function deriveRootLinkKeysDirect(
  idBytes: Uint8Array,
  serviceDomain: string
): Promise<LinkKeys> {
  if (idBytes.length !== 8) throw new Error('ID must be exactly 8 bytes.');
  const salt = deriveRootKeySalt(serviceDomain);
  let rootKey: Uint8Array | undefined;
  try {
    rootKey = await argon2dAsync(idBytes, salt, {
      version: ROOT_KEY_ARGON2D_V2.version,
      m: ROOT_KEY_ARGON2D_V2.m,
      t: ROOT_KEY_ARGON2D_V2.t,
      p: ROOT_KEY_ARGON2D_V2.p,
      dkLen: ROOT_KEY_ARGON2D_V2.dkLen,
      asyncTick: 8
    });
    return deriveLinkKeys(rootKey, serviceDomain);
  } catch (error) {
    if (error instanceof Error && error.message.startsWith('Service domain')) throw error;
    throw new Error(ROOT_KEY_DERIVATION_UNAVAILABLE);
  } finally {
    salt.fill(0);
    rootKey?.fill(0);
  }
}
