import { derivePasswordKeyDirect } from './password-derivation';

type WorkerResponse =
  | { requestId: number; key: Uint8Array }
  | { requestId: number; error: string };

let nextRequestId = 1;

function abortReason(signal?: AbortSignal): unknown {
  return signal?.reason ?? new DOMException('Aborted', 'AbortError');
}

async function deriveWithoutWorker(
  password: string,
  salt: Uint8Array,
  signal?: AbortSignal
): Promise<Uint8Array> {
  if (signal?.aborted) throw abortReason(signal);
  const saltCopy = salt.slice();
  try {
    if (signal?.aborted) throw abortReason(signal);
    const key = await derivePasswordKeyDirect(password, saltCopy);
    if (signal?.aborted) {
      key.fill(0);
      throw abortReason(signal);
    }
    return key;
  } finally {
    saltCopy.fill(0);
  }
}

export function derivePasswordKey(
  password: string,
  salt: Uint8Array,
  signal?: AbortSignal
): Promise<Uint8Array> {
  if (signal?.aborted) return Promise.reject(abortReason(signal));
  if (typeof Worker !== 'function') return deriveWithoutWorker(password, salt, signal);

  let worker: Worker;
  try {
    worker = new Worker(new URL('./password.worker.ts', import.meta.url), { type: 'module' });
  } catch {
    return deriveWithoutWorker(password, salt, signal);
  }

  const requestId = nextRequestId++;
  return new Promise<Uint8Array>((resolve, reject) => {
    let settled = false;
    let fallbackStarted = false;
    const cleanup = () => {
      signal?.removeEventListener('abort', onAbort);
      worker.terminate();
    };
    const resolveOnce = (key: Uint8Array) => {
      if (settled) {
        key.fill(0);
        return;
      }
      settled = true;
      cleanup();
      resolve(key);
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
      void deriveWithoutWorker(password, salt, signal).then(resolveOnce, rejectOnce);
    };

    signal?.addEventListener('abort', onAbort, { once: true });
    worker.addEventListener('error', startFallback, { once: true });
    worker.addEventListener('message', (event: MessageEvent<WorkerResponse>) => {
      if (fallbackStarted || event.data.requestId !== requestId) return;
      if ('error' in event.data) rejectOnce(new Error(event.data.error));
      else resolveOnce(event.data.key);
    });

    const requestSalt = salt.slice();
    try {
      worker.postMessage({ requestId, password, salt: requestSalt }, [requestSalt.buffer]);
    } catch {
      requestSalt.fill(0);
      startFallback();
    }
  });
}
