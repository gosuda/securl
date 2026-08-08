import { create, fromBinary, toBinary } from '@bufbuild/protobuf';
import { describe, expect, it } from 'vitest';
import {
  SafeBrowsingFullHashSchema,
  SafeBrowsingLookupRequestSchema,
  SafeBrowsingLookupResponseSchema,
  type SafeBrowsingLookupRequest
} from '../gen/securl/v1/api_pb.js';
import { lookupSafeBrowsingPrefixes } from './client';
import type { SafeBrowsingHash } from './url-hash';

describe('private Safe Browsing prefix proxy', () => {
  it('sends only deduplicated four-byte prefixes to the SecURL API', async () => {
    const fullHash = new Uint8Array(32).fill(7);
    const localHashes: SafeBrowsingHash[] = [
      { expression: 'example.com/', fullHash, prefix: new Uint8Array([1, 2, 3, 4]) },
      { expression: 'example.com/path', fullHash, prefix: new Uint8Array([1, 2, 3, 4]) }
    ];
    let capturedUrl = '';
    let capturedRequest: SafeBrowsingLookupRequest | undefined;
    const responseBody = toBinary(
      SafeBrowsingLookupResponseSchema,
      create(SafeBrowsingLookupResponseSchema, {
        fullHashes: [
          create(SafeBrowsingFullHashSchema, {
            fullHash,
            threatType: 'MALWARE',
            cacheSeconds: 60
          })
        ]
      })
    );
    const fakeFetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      capturedUrl = String(input);
      capturedRequest = fromBinary(
        SafeBrowsingLookupRequestSchema,
        init?.body as Uint8Array
      );
      return new Response(responseBody, {
        status: 200,
        headers: { 'Content-Type': 'application/x-protobuf' }
      });
    }) as typeof fetch;

    const response = await lookupSafeBrowsingPrefixes('https://api.example', localHashes, undefined, fakeFetch);
    expect(capturedUrl).toBe('https://api.example/api/v1/safe-browsing/lookup');
    expect(capturedUrl).not.toContain('example.com');
    expect(capturedRequest!.hashPrefixes).toEqual([new Uint8Array([1, 2, 3, 4])]);
    expect(response.fullHashes).toHaveLength(1);
  });

  it('rejects full hashes or prefix counts outside the protocol', async () => {
    const fullHash = new Uint8Array(32);
    await expect(
      lookupSafeBrowsingPrefixes('', [
        { expression: 'x', fullHash, prefix: new Uint8Array(3) }
      ])
    ).rejects.toThrow(/invalid lengths/);
    await expect(
      lookupSafeBrowsingPrefixes(
        '',
        Array.from({ length: 31 }, (_, index) => ({
          expression: String(index),
          fullHash,
          prefix: new Uint8Array([index, 0, 0, 0])
        }))
      )
    ).rejects.toThrow(/1 and 30/);
  });
});
