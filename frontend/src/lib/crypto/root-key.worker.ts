import { argon2idAsync } from '@noble/hashes/argon2.js';
import { deriveLinkKeys, deriveRootKeySalt, type LinkKeys } from './protocol';
import {
  ROOT_KEY_ARGON2ID_V2,
  ROOT_KEY_DERIVATION_UNAVAILABLE
} from './root-key-profile';

export async function deriveRootLinkKeys(
  idBytes: Uint8Array,
  serviceDomain: string
): Promise<LinkKeys> {
  if (idBytes.length !== 8) throw new Error('ID must be exactly 8 bytes.');
  const salt = deriveRootKeySalt(serviceDomain);
  let rootKey: Uint8Array | undefined;
  try {
    rootKey = await argon2idAsync(idBytes, salt, {
      version: ROOT_KEY_ARGON2ID_V2.version,
      m: ROOT_KEY_ARGON2ID_V2.m,
      t: ROOT_KEY_ARGON2ID_V2.t,
      p: ROOT_KEY_ARGON2ID_V2.p,
      dkLen: ROOT_KEY_ARGON2ID_V2.dkLen,
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

type WorkerRequest = {
  requestId: number;
  idBytes: Uint8Array;
  serviceDomain: string;
};

type WorkerResponse =
  | { requestId: number; storageKey: Uint8Array; encryptionKeyMaterial: Uint8Array }
  | { requestId: number; error: string };

const workerScope = globalThis as typeof globalThis & {
  postMessage(message: WorkerResponse, transfer?: Transferable[]): void;
};

if (typeof document === 'undefined' && typeof workerScope.postMessage === 'function') {
  workerScope.addEventListener('message', async (event: MessageEvent<WorkerRequest>) => {
    const { requestId, idBytes, serviceDomain } = event.data;
    try {
      const keys = await deriveRootLinkKeys(idBytes, serviceDomain);
      workerScope.postMessage(
        {
          requestId,
          storageKey: keys.storageKey,
          encryptionKeyMaterial: keys.encryptionKeyMaterial
        },
        [keys.storageKey.buffer, keys.encryptionKeyMaterial.buffer]
      );
    } catch (error) {
      workerScope.postMessage({
        requestId,
        error: error instanceof Error ? error.message : ROOT_KEY_DERIVATION_UNAVAILABLE
      });
    } finally {
      idBytes.fill(0);
    }
  });
}
