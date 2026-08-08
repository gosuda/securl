import { create, fromBinary, toBinary } from '@bufbuild/protobuf';
import {
  SafeBrowsingLookupRequestSchema,
  SafeBrowsingLookupResponseSchema,
  type SafeBrowsingLookupResponse
} from '../gen/securl/v1/api_pb.js';
import type { SafeBrowsingHash } from './url-hash';

export async function lookupSafeBrowsingPrefixes(
  apiBaseUrl: string,
  localHashes: readonly SafeBrowsingHash[],
  signal?: AbortSignal,
  fetchImplementation: typeof fetch = fetch
): Promise<SafeBrowsingLookupResponse> {
  const seen = new Set<string>();
  const prefixes: Uint8Array[] = [];
  for (const localHash of localHashes) {
    if (localHash.prefix.length !== 4 || localHash.fullHash.length !== 32) {
      throw new Error('Safe Browsing hashes have invalid lengths.');
    }
    const key = [...localHash.prefix].join(',');
    if (!seen.has(key)) {
      seen.add(key);
      prefixes.push(localHash.prefix.slice());
    }
  }
  if (prefixes.length < 1 || prefixes.length > 30) {
    throw new Error('Safe Browsing lookup requires between 1 and 30 prefixes.');
  }

  const body = toBinary(
    SafeBrowsingLookupRequestSchema,
    create(SafeBrowsingLookupRequestSchema, { hashPrefixes: prefixes }),
    { writeUnknownFields: false }
  );
  const response = await fetchImplementation(
    `${apiBaseUrl.replace(/\/$/, '')}/api/v1/safe-browsing/lookup`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-protobuf' },
      body,
      signal
    }
  );
  if (!response.ok) {
    throw new Error(`Safe Browsing lookup failed with status ${response.status}.`);
  }
  if (!response.headers.get('Content-Type')?.startsWith('application/x-protobuf')) {
    throw new Error('Safe Browsing lookup returned an invalid content type.');
  }
  const decoded = fromBinary(
    SafeBrowsingLookupResponseSchema,
    new Uint8Array(await response.arrayBuffer())
  );
  for (const fullHash of decoded.fullHashes) {
    if (fullHash.fullHash.length !== 32) {
      throw new Error('Safe Browsing lookup returned an invalid full hash.');
    }
  }
  return decoded;
}
