import { describe, expect, it } from 'vitest';
import { normalizeServiceDomain } from './domain';

describe('service domain normalization', () => {
  it('normalizes Unicode domains to lowercase canonical Punycode', () => {
    expect(normalizeServiceDomain('BÜCHER.Example.')).toBe('xn--bcher-kva.example');
    expect(normalizeServiceDomain('mañana.com')).toBe('xn--maana-pta.com');
    expect(normalizeServiceDomain('例え.テスト')).toBe('xn--r8jz45g.xn--zckzah');
    expect(normalizeServiceDomain('faß.de')).toBe('xn--fa-hia.de');
    expect(normalizeServiceDomain('example。com')).toBe('example.com');
    expect(normalizeServiceDomain('e\u0301xample.com')).toBe(
      normalizeServiceDomain('éxample.com')
    );
  });

  it('normalizes legal IP encodings and preserves development localhost', () => {
    expect(normalizeServiceDomain('0177.0.0.1')).toBe('127.0.0.1');
    expect(normalizeServiceDomain('[2001:0DB8:0:0::1]')).toBe('[2001:db8::1]');
    expect(normalizeServiceDomain('localhost')).toBe('localhost');
  });

  it('rejects origins, ports, paths, credentials, malformed labels, and whitespace', () => {
    for (const input of [
      ' https://example.com',
      'https://example.com',
      'example.com:443',
      'user@example.com',
      'example.com/path',
      '.example.com',
      'example..com',
      '-example.com',
      'example-.com',
      `${'a'.repeat(64)}.com`,
      ''
    ]) {
      expect(() => normalizeServiceDomain(input), input).toThrow();
    }
  });
});
