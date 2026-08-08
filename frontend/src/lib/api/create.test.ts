import { describe, expect, it } from 'vitest';
import {
  CreateConflictError,
  CreateTransportError,
  MAX_CREATE_ATTEMPTS,
  createWithCollisionRetries
} from './create';

describe('idempotent create retry policy', () => {
  it('regenerates the whole artifact only after an HTTP conflict', async () => {
    let builds = 0;
    const submitted: number[] = [];
    const result = await createWithCollisionRetries(
      () => ({ generation: ++builds }),
      async (artifact) => {
        submitted.push(artifact.generation);
        if (artifact.generation < 3) throw new CreateConflictError();
        return 'created';
      }
    );

    expect(builds).toBe(3);
    expect(submitted).toEqual([1, 2, 3]);
    expect(result).toEqual({ artifact: { generation: 3 }, response: 'created' });
  });

  it('retries one transport failure with the exact same artifact', async () => {
    let builds = 0;
    const submitted: object[] = [];
    const result = await createWithCollisionRetries(
      () => ({ generation: ++builds }),
      async (artifact) => {
        submitted.push(artifact);
        if (submitted.length === 1) throw new CreateTransportError();
        return 'replayed';
      }
    );

    expect(builds).toBe(1);
    expect(submitted).toHaveLength(2);
    expect(submitted[0]).toBe(submitted[1]);
    expect(result.response).toBe('replayed');
  });

  it('does not regenerate on dependency or validation errors', async () => {
    let builds = 0;
    await expect(
      createWithCollisionRetries(
        () => ({ generation: ++builds }),
        async () => {
          throw new Error('dependency unavailable');
        }
      )
    ).rejects.toThrow(/dependency unavailable/);
    expect(builds).toBe(1);
  });

  it('stops after five actual conflicts', async () => {
    let builds = 0;
    await expect(
      createWithCollisionRetries(
        () => ({ generation: ++builds }),
        async () => {
          throw new CreateConflictError();
        }
      )
    ).rejects.toThrow(/5 attempts/);
    expect(builds).toBe(MAX_CREATE_ATTEMPTS);
  });
});
