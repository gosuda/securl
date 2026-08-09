import { deriveRootLinkKeysDirect } from './root-key-derivation';
import type { LinkKeys } from './protocol';

type WorkerResponse =
  | { requestId: number; storageKey: Uint8Array; encryptionKeyMaterial: Uint8Array }
  | { requestId: number; error: string };

let nextRequestId = 1;

function abortReason(signal?: AbortSignal): unknown {
  return signal?.reason ?? new DOMException('Aborted', 'AbortError');
}

async function deriveWithoutWorker(
  idBytes: Uint8Array,
  serviceDomain: string,
  signal?: AbortSignal
): Promise<LinkKeys> {
  if (signal?.aborted) throw abortReason(signal);
  const idCopy = idBytes.slice();
  try {
    if (signal?.aborted) throw abortReason(signal);
    const keys = await deriveRootLinkKeysDirect(idCopy, serviceDomain);
    if (signal?.aborted) {
      keys.storageKey.fill(0);
      keys.encryptionKeyMaterial.fill(0);
      throw abortReason(signal);
    }
    return keys;
  } finally {
    idCopy.fill(0);
  }
}

export function deriveRootLinkKeys(
  idBytes: Uint8Array,
  serviceDomain: string,
  signal?: AbortSignal
): Promise<LinkKeys> {
  if (signal?.aborted) return Promise.reject(abortReason(signal));
  if (typeof Worker !== 'function') return deriveWithoutWorker(idBytes, serviceDomain, signal);

  let worker: Worker;
  try {
    worker = new Worker(new URL('./root-key.worker.ts', import.meta.url), { type: 'module' });
  } catch {
    return deriveWithoutWorker(idBytes, serviceDomain, signal);
  }

  const requestId = nextRequestId++;
  return new Promise<LinkKeys>((resolve, reject) => {
    let settled = false;
    let fallbackStarted = false;
    const cleanup = () => {
      signal?.removeEventListener('abort', onAbort);
      worker.terminate();
    };
    const resolveOnce = (keys: LinkKeys) => {
      if (settled) {
        keys.storageKey.fill(0);
        keys.encryptionKeyMaterial.fill(0);
        return;
      }
      settled = true;
      cleanup();
      resolve(keys);
    };
    const rejectOnce = (error: unknown) => {
      if (settled) return;
      settled = true;
      cleanup();
      reject(error);
    };
    const onAbort = () => rejectOnce(abortReason(signal));
    const startFallback = () => {
      if (settled || fallbackStarted) return;
      fallbackStarted = true;
      worker.terminate();
      void deriveWithoutWorker(idBytes, serviceDomain, signal).then(resolveOnce, rejectOnce);
    };

    signal?.addEventListener('abort', onAbort, { once: true });
    worker.addEventListener('error', startFallback, { once: true });
    worker.addEventListener('message', (event: MessageEvent<WorkerResponse>) => {
      if (fallbackStarted || event.data.requestId !== requestId) return;
      if ('error' in event.data) {
        rejectOnce(new Error(event.data.error));
      } else {
        resolveOnce({
          storageKey: event.data.storageKey,
          encryptionKeyMaterial: event.data.encryptionKeyMaterial
        });
      }
    });

    const requestIdBytes = idBytes.slice();
    try {
      worker.postMessage(
        { requestId, idBytes: requestIdBytes, serviceDomain },
        [requestIdBytes.buffer]
      );
    } catch {
      requestIdBytes.fill(0);
      startFallback();
    }
  });
}
