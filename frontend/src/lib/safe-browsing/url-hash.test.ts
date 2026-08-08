import { create } from '@bufbuild/protobuf';
import { bytesToHex } from '@noble/hashes/utils.js';
import { describe, expect, it } from 'vitest';
import { SafeBrowsingFullHashSchema } from '../gen/securl/v1/api_pb.js';
import {
  canonicalizeSafeBrowsingUrl,
  findBlockingMatch,
  safeBrowsingExpressions,
  sha256,
  type SafeBrowsingHash
} from './url-hash';

describe('Google Safe Browsing URL hashing', () => {
  it('matches official canonicalization fixtures', () => {
    const fixtures = new Map([
      ['http://host/%25%32%35', 'http://host/%25'],
      ['http://host/%25%32%35%25%32%35', 'http://host/%25%25'],
      ['http://host/%2525252525252525', 'http://host/%25'],
      ['http://host/asdf%25%32%35asd', 'http://host/asdf%25asd'],
      ['http://3279880203/blah', 'http://195.127.0.11/blah'],
      ['http://www.google.com/blah/..', 'http://www.google.com/'],
      ['www.google.com', 'http://www.google.com/'],
      ['http://www.GOOgle.com.../', 'http://www.google.com/'],
      ['http://www.google.com/foo\tbar\rbaz\n2', 'http://www.google.com/foobarbaz2'],
      ['http://www.gotaport.com:1234/', 'http://www.gotaport.com/'],
      ['http://host.com//twoslashes?more//slashes', 'http://host.com/twoslashes?more//slashes'],
      ['http://host%23.com/%257Ea%2521b%2540c%2523d', 'http://host%23.com/~a!b@c%23d']
    ]);

    for (const [input, expected] of fixtures) {
      expect(canonicalizeSafeBrowsingUrl(input), input).toBe(expected);
    }
  });

  it('generates the official host suffix and path prefix expressions', () => {
    expect(safeBrowsingExpressions('http://a.b.c/1/2.html?param=1')).toEqual([
      'a.b.c/1/2.html?param=1',
      'a.b.c/1/2.html',
      'a.b.c/',
      'a.b.c/1/',
      'b.c/1/2.html?param=1',
      'b.c/1/2.html',
      'b.c/',
      'b.c/1/'
    ]);
    expect(safeBrowsingExpressions('http://1.2.3.4/1/')).toEqual([
      '1.2.3.4/1/',
      '1.2.3.4/'
    ]);
    expect(safeBrowsingExpressions('http://a.b.c.d.e.f.g/1.html')).toHaveLength(10);
  });

  it('uses Web Crypto SHA-256 and extracts the first four bytes', async () => {
    const fullHash = await sha256('abc');
    expect(bytesToHex(fullHash)).toBe(
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
    );
    expect(bytesToHex(fullHash.slice(0, 4))).toBe('ba7816bf');
  });

  it('blocks only matching known threats without the CANARY attribute', async () => {
    const fullHash = await sha256('abc');
    const local: SafeBrowsingHash[] = [
      { expression: 'abc', fullHash, prefix: fullHash.slice(0, 4) }
    ];
    const malware = create(SafeBrowsingFullHashSchema, {
      fullHash,
      threatType: 'MALWARE',
      attributes: [],
      cacheSeconds: 60
    });
    expect(findBlockingMatch(local, [malware])).toBe(malware);
    expect(
      findBlockingMatch(local, [
        create(SafeBrowsingFullHashSchema, {
          fullHash,
          threatType: 'MALWARE',
          attributes: ['CANARY']
        })
      ])
    ).toBeUndefined();
    expect(
      findBlockingMatch(local, [
        create(SafeBrowsingFullHashSchema, { fullHash, threatType: 'FUTURE_THREAT' })
      ])
    ).toBeUndefined();
  });
});
