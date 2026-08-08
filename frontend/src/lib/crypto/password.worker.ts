import { argon2idAsync } from '@noble/hashes/argon2.js';
import { ARGON2ID_V1, PASSWORD_DERIVATION_UNAVAILABLE } from './password-profile';


const textEncoder = new TextEncoder();

export async function derivePasswordKey(password: string, salt: Uint8Array): Promise<Uint8Array> {
  if (salt.length !== 16) {
    throw new Error('Password salt must be exactly 16 bytes.');
  }

  const passwordBytes = textEncoder.encode(password);
  if (passwordBytes.length < 1 || passwordBytes.length > 1024) {
    passwordBytes.fill(0);
    throw new Error('Password must be between 1 and 1024 UTF-8 bytes.');
  }

  try {
    return await argon2idAsync(passwordBytes, salt, {
      version: ARGON2ID_V1.version,
      m: ARGON2ID_V1.m,
      t: ARGON2ID_V1.t,
      p: ARGON2ID_V1.p,
      dkLen: ARGON2ID_V1.dkLen,
      asyncTick: 8
    });
  } catch {
    throw new Error(PASSWORD_DERIVATION_UNAVAILABLE);
  } finally {
    passwordBytes.fill(0);
  }
}

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
      const key = await derivePasswordKey(password, salt);
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
