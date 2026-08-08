import { create, fromBinary, toBinary } from '@bufbuild/protobuf';
import { env } from '$env/dynamic/public';
import {
  AccessEnvelopeRequestSchema,
  AccessEnvelopeResponseSchema,
  CreateEnvelopeRequestSchema,
  CreateEnvelopeResponseSchema,
  ErrorResponseSchema,
  GetEnvelopeMetadataResponseSchema,
  RuntimeConfigSchema,
  type CreateEnvelopeRequest,
  type CreateEnvelopeResponse,
  type GetEnvelopeMetadataResponse,
  type RuntimeConfig
} from '../gen/securl/v1/api_pb.js';
import { EnvelopeSchema, type Envelope } from '../gen/securl/v1/envelope_pb.js';
import { CreateConflictError, CreateTransportError } from './create';

export const API_BASE_URL = (env.PUBLIC_SECURL_API_BASE_URL ?? '').replace(/\/$/, '');

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
  }
}

async function protobufBody(response: Response): Promise<Uint8Array> {
  if (!response.headers.get('Content-Type')?.startsWith('application/x-protobuf')) {
    throw new ApiError(response.status, 'internal', 'The SecURL API returned an invalid response.');
  }
  return new Uint8Array(await response.arrayBuffer());
}

async function throwApiError(response: Response): Promise<never> {
  try {
    const decoded = fromBinary(ErrorResponseSchema, await protobufBody(response));
    throw new ApiError(response.status, decoded.code || 'internal', decoded.message || 'Request failed.');
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(response.status, 'internal', 'The SecURL API request failed.');
  }
}

export async function getRuntimeConfig(signal?: AbortSignal): Promise<RuntimeConfig> {
  const response = await fetch(`${API_BASE_URL}/api/v1/config`, { signal });
  if (!response.ok) return throwApiError(response);
  return fromBinary(RuntimeConfigSchema, await protobufBody(response));
}

export async function submitEnvelope(
  request: CreateEnvelopeRequest,
  signal?: AbortSignal
): Promise<CreateEnvelopeResponse> {
  const body = toBinary(CreateEnvelopeRequestSchema, request, { writeUnknownFields: false });
  let response: Response;
  try {
    response = await fetch(`${API_BASE_URL}/api/v1/envelopes`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-protobuf' },
      body,
      signal
    });
  } catch (error) {
    if (signal?.aborted) throw error;
    throw new CreateTransportError();
  }
  if (response.status === 409) throw new CreateConflictError();
  if (!response.ok) return throwApiError(response);
  return fromBinary(CreateEnvelopeResponseSchema, await protobufBody(response));
}

export async function getEnvelopeMetadata(
  storageKey: string,
  signal?: AbortSignal
): Promise<GetEnvelopeMetadataResponse> {
  const response = await fetch(
    `${API_BASE_URL}/api/v1/envelopes/${storageKey}/metadata`,
    { signal, cache: 'no-store' }
  );
  if (!response.ok) return throwApiError(response);
  return fromBinary(GetEnvelopeMetadataResponseSchema, await protobufBody(response));
}

export async function getEnvelope(storageKey: string, signal?: AbortSignal): Promise<Envelope> {
  const response = await fetch(`${API_BASE_URL}/api/v1/envelopes/${storageKey}`, {
    signal,
    cache: 'no-cache'
  });
  if (!response.ok) return throwApiError(response);
  return fromBinary(EnvelopeSchema, await protobufBody(response));
}

export async function accessEnvelope(
  storageKey: string,
  captchaToken: string,
  signal?: AbortSignal
): Promise<{ envelope: Envelope; captchaKey: Uint8Array; expiresAtUnix: bigint }> {
  const body = toBinary(
    AccessEnvelopeRequestSchema,
    create(AccessEnvelopeRequestSchema, { captchaToken }),
    { writeUnknownFields: false }
  );
  const response = await fetch(`${API_BASE_URL}/api/v1/envelopes/${storageKey}/access`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-protobuf' },
    body,
    signal
  });
  if (!response.ok) return throwApiError(response);
  const decoded = fromBinary(AccessEnvelopeResponseSchema, await protobufBody(response));
  if (!decoded.envelope) {
    throw new ApiError(500, 'internal', 'The SecURL API returned an incomplete envelope.');
  }
  return {
    envelope: decoded.envelope,
    captchaKey: decoded.captchaKey,
    expiresAtUnix: decoded.expiresAtUnix
  };
}
