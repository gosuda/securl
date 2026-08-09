import { deriveRootLinkKeysDirect } from './root-key-derivation';
import { ROOT_KEY_DERIVATION_UNAVAILABLE } from './root-key-profile';

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
      const keys = await deriveRootLinkKeysDirect(idBytes, serviceDomain);
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
