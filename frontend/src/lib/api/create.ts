export const MAX_CREATE_ATTEMPTS = 5;

export class CreateConflictError extends Error {
  constructor() {
    super('Storage key conflict.');
    this.name = 'CreateConflictError';
  }
}

export class CreateTransportError extends Error {
  constructor(message = 'Create request failed before a response was received.') {
    super(message);
    this.name = 'CreateTransportError';
  }
}

export interface CreateResult<Artifact, Response> {
  artifact: Artifact;
  response: Response;
}

export async function createWithCollisionRetries<Artifact, Response>(
  buildArtifact: () => Promise<Artifact> | Artifact,
  submit: (artifact: Artifact) => Promise<Response>
): Promise<CreateResult<Artifact, Response>> {
  for (let attempt = 0; attempt < MAX_CREATE_ATTEMPTS; attempt += 1) {
    const artifact = await buildArtifact();
    try {
      return { artifact, response: await submit(artifact) };
    } catch (error) {
      if (error instanceof CreateTransportError) {
        return { artifact, response: await submit(artifact) };
      }
      if (!(error instanceof CreateConflictError)) throw error;
    }
  }
  throw new Error('Could not create a collision-free protected link after 5 attempts.');
}
