import type { LinkKeys } from './protocol';
import { ROOT_KEY_DERIVATION_UNAVAILABLE } from './root-key-profile';

type WorkerResponse =
  | { requestId: number; storageKey: Uint8Array; encryptionKeyMaterial: Uint8Array }
  | { requestId: number; error: string };

let nextRequestId = 1;

export function deriveRootLinkKeysInWorker(
  idBytes: Uint8Array,
  serviceDomain: string,
  signal?: AbortSignal
): Promise<LinkKeys> {
  if (signal?.aborted) return Promise.reject(signal.reason);
  const worker = new Worker(new URL('./root-key.worker.ts', import.meta.url), { type: 'module' });
  const requestId = nextRequestId++;
  const { promise, resolve, reject } = Promise.withResolvers<LinkKeys>();
  const cleanup = () => {
    signal?.removeEventListener('abort', onAbort);
    worker.terminate();
  };
  const onAbort = () => {
    cleanup();
    reject(signal?.reason ?? new DOMException('Aborted', 'AbortError'));
  };
  signal?.addEventListener('abort', onAbort, { once: true });
  worker.addEventListener('error', () => {
    cleanup();
    reject(new Error(ROOT_KEY_DERIVATION_UNAVAILABLE));
  });
  worker.addEventListener('message', (event: MessageEvent<WorkerResponse>) => {
    if (event.data.requestId !== requestId) return;
    cleanup();
    if ('error' in event.data) {
      reject(new Error(event.data.error));
    } else {
      resolve({
        storageKey: event.data.storageKey,
        encryptionKeyMaterial: event.data.encryptionKeyMaterial
      });
    }
  });
  worker.postMessage({ requestId, idBytes: idBytes.slice(), serviceDomain });
  return promise;
}
