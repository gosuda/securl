import { PASSWORD_DERIVATION_UNAVAILABLE } from './password-profile';

type WorkerResponse =
  | { requestId: number; key: Uint8Array }
  | { requestId: number; error: string };

let nextRequestId = 1;

export function derivePasswordKeyInWorker(
  password: string,
  salt: Uint8Array,
  signal?: AbortSignal
): Promise<Uint8Array> {
  if (signal?.aborted) return Promise.reject(signal.reason);
  const worker = new Worker(new URL('./password.worker.ts', import.meta.url), { type: 'module' });
  const requestId = nextRequestId++;
  const { promise, resolve, reject } = Promise.withResolvers<Uint8Array>();
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
    reject(new Error(PASSWORD_DERIVATION_UNAVAILABLE));
  });
  worker.addEventListener('message', (event: MessageEvent<WorkerResponse>) => {
    if (event.data.requestId !== requestId) return;
    cleanup();
    if ('error' in event.data) {
      reject(new Error(event.data.error));
    } else {
      resolve(event.data.key);
    }
  });
  worker.postMessage({ requestId, password, salt: salt.slice() });
  return promise;
}
