import { derivePasswordKeyDirect } from './password-derivation';
import { PASSWORD_DERIVATION_UNAVAILABLE } from './password-profile';

type WorkerRequest = {
  requestId: number;
  password: string;
  salt: Uint8Array;
};

type WorkerResponse =
  | { requestId: number; key: Uint8Array }
  | { requestId: number; error: string };

const workerScope = globalThis as typeof globalThis & {
  postMessage(message: WorkerResponse, transfer?: Transferable[]): void;
};

if (typeof document === 'undefined' && typeof workerScope.postMessage === 'function') {
  workerScope.addEventListener('message', async (event: MessageEvent<WorkerRequest>) => {
    const { requestId, password, salt } = event.data;
    try {
      const key = await derivePasswordKeyDirect(password, salt);
      const responseKey = key.slice();
      key.fill(0);
      workerScope.postMessage({ requestId, key: responseKey }, [responseKey.buffer]);
    } catch (error) {
      workerScope.postMessage({
        requestId,
        error: error instanceof Error ? error.message : PASSWORD_DERIVATION_UNAVAILABLE
      });
    }
  });
}
