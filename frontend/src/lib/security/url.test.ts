import { describe, expect, it } from 'vitest';
import { validateDestination } from './url';

describe('destination URL validation', () => {
  it('returns one canonical HTTP or HTTPS URL after trimming ASCII edge whitespace', () => {
    expect(validateDestination(' \thttps://ExAmPle.com:443/a/../b?x=1#part\r\n').href).toBe(
      'https://example.com/b?x=1#part'
    );
    expect(validateDestination('http://example.com').href).toBe('http://example.com/');
    expect(validateDestination('https://bücher.example/').hostname).toBe('xn--bcher-kva.example');
  });

  it('defaults inputs without a protocol to HTTPS', () => {
    expect(validateDestination('example.com/path?x=1#part').href).toBe(
      'https://example.com/path?x=1#part'
    );
    expect(validateDestination('//example.com/path').href).toBe('https://example.com/path');
    expect(validateDestination('example.com:8443/path').href).toBe('https://example.com:8443/path');
    expect(validateDestination('bücher.example/path').hostname).toBe('xn--bcher-kva.example');
  });

  it('rejects schemes, credentials, controls, and oversized inputs', () => {
    for (const input of [
      'javascript:alert(1)',
      'data:text/plain,hello',
      'mailto:user@example.com',
      'file:///tmp/example',
      'ftp://example.com/file',
      'https://user@example.com/',
      'https://user:password@example.com/',
      'https://example.com/a\u0000b',
      `https://example.com/${'a'.repeat(4097)}`
    ]) {
      expect(() => validateDestination(input)).toThrow();
    }
  });

  it('rejects inputs whose canonical percent-encoded URL exceeds the byte limit', () => {
    expect(() => validateDestination(`example.com/${'가'.repeat(1000)}`)).toThrow(
      /between 1 and 4096 UTF-8 bytes/
    );
  });

  it('rejects local names and non-public IPv4 literals, including alternate URL forms', () => {
    for (const input of [
      'http://localhost/',
      'http://service.localhost/',
      'http://printer.local/',
      'http://localhost./',
      'http://service.localhost./',
      'http://printer.local./',
      'http://0.0.0.0/',
      'http://10.1.2.3/',
      'http://127.0.0.1/',
      'http://127.1/',
      'http://169.254.1.1/',
      'http://172.16.0.1/',
      'http://192.168.0.1/',
      'http://224.0.0.1/',
      'http://255.255.255.255/'
    ]) {
      expect(() => validateDestination(input), input).toThrow(/publicly routable/);
    }
  });

  it('rejects non-public IPv6 literals and accepts global addresses', () => {
    for (const input of [
      'http://[::]/',
      'http://[::1]/',
      'http://[fc00::1]/',
      'http://[fe80::1]/',
      'http://[ff02::1]/',
      'http://[::ffff:127.0.0.1]/',
      'http://[::ffff:192.168.1.1]/'
    ]) {
      expect(() => validateDestination(input), input).toThrow(/publicly routable/);
    }
    expect(validateDestination('https://[2606:4700:4700::1111]/').hostname).toBe(
      '[2606:4700:4700::1111]'
    );
  });
});
