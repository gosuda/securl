import type { SafeBrowsingFullHash } from '../gen/securl/v1/api_pb.js';

const textEncoder = new TextEncoder();
const BLOCKING_THREAT_TYPES = new Set([
  'MALWARE',
  'SOCIAL_ENGINEERING',
  'UNWANTED_SOFTWARE',
  'POTENTIALLY_HARMFUL_APPLICATION'
]);

export interface SafeBrowsingHash {
  expression: string;
  fullHash: Uint8Array;
  prefix: Uint8Array;
}

function percentDecodeRepeatedly(input: string): string {
  let decoded = input;
  for (;;) {
    const next = decoded.replace(/%([0-9a-f]{2})/gi, (_, hex: string) =>
      String.fromCharCode(Number.parseInt(hex, 16))
    );
    if (next === decoded) return decoded;
    decoded = next;
  }
}

function normalizeHostname(hostname: string): string {
  let normalized = hostname.replace(/^\.+|\.+$/g, '').replace(/\.+/g, '.').toLowerCase();
  if (/^[a-z0-9.\-[\]:\u0080-\uffff]+$/i.test(normalized)) {
    try {
      normalized = new URL(`http://${normalized}/`).hostname.toLowerCase();
    } catch {
      // Preserve unusual but parseable-by-the-caller bytes for the escaping pass below.
    }
  }
  return normalized;
}

function normalizePath(path: string): string {
  const collapsed = (path.startsWith('/') ? path : `/${path}`).replace(/\/{2,}/g, '/');
  const trailingSlash =
    collapsed.endsWith('/') || collapsed.endsWith('/.') || collapsed.endsWith('/..');
  const segments: string[] = [];
  for (const segment of collapsed.split('/')) {
    if (segment === '' || segment === '.') continue;
    if (segment === '..') {
      segments.pop();
      continue;
    }
    segments.push(segment);
  }

  let normalized = `/${segments.join('/')}`;
  if (trailingSlash && normalized !== '/') normalized += '/';
  return normalized;
}

function escapeUnsafe(input: string): string {
  let escaped = '';
  for (const character of input) {
    const codePoint = character.codePointAt(0)!;
    if (codePoint <= 0xff) {
      if (codePoint <= 32 || codePoint >= 127 || character === '#' || character === '%') {
        escaped += `%${codePoint.toString(16).toUpperCase().padStart(2, '0')}`;
      } else {
        escaped += character;
      }
      continue;
    }
    for (const byte of textEncoder.encode(character)) {
      escaped += `%${byte.toString(16).toUpperCase().padStart(2, '0')}`;
    }
  }
  return escaped;
}

export function canonicalizeSafeBrowsingUrl(input: string): string {
  let cleaned = input.replace(/[\t\r\n]/g, '').replace(/^ +| +$/g, '');
  const fragmentIndex = cleaned.indexOf('#');
  if (fragmentIndex >= 0) cleaned = cleaned.slice(0, fragmentIndex);
  cleaned = percentDecodeRepeatedly(cleaned);
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(cleaned)) cleaned = `http://${cleaned}`;

  const schemeEnd = cleaned.indexOf('://');
  const scheme = cleaned.slice(0, schemeEnd).toLowerCase();
  const afterScheme = cleaned.slice(schemeEnd + 3);
  const authorityEnd = afterScheme.search(/[/?]/);
  let authority = authorityEnd < 0 ? afterScheme : afterScheme.slice(0, authorityEnd);
  const remainder = authorityEnd < 0 ? '' : afterScheme.slice(authorityEnd);
  const userInfoEnd = authority.lastIndexOf('@');
  if (userInfoEnd >= 0) authority = authority.slice(userInfoEnd + 1);

  let hostname = authority;
  if (hostname.startsWith('[')) {
    const bracketEnd = hostname.indexOf(']');
    if (bracketEnd >= 0) hostname = hostname.slice(0, bracketEnd + 1);
  } else {
    const portSeparator = hostname.lastIndexOf(':');
    if (portSeparator >= 0 && /^\d*$/.test(hostname.slice(portSeparator + 1))) {
      hostname = hostname.slice(0, portSeparator);
    }
  }
  hostname = normalizeHostname(hostname);

  let path = '/';
  let query: string | undefined;
  if (remainder.startsWith('?')) {
    query = remainder.slice(1);
  } else if (remainder !== '') {
    const queryIndex = remainder.indexOf('?');
    path = queryIndex < 0 ? remainder : remainder.slice(0, queryIndex);
    if (queryIndex >= 0) query = remainder.slice(queryIndex + 1);
  }
  path = normalizePath(path);

  const suffix = query === undefined ? path : `${path}?${query}`;
  return `${scheme}://${escapeUnsafe(hostname)}${escapeUnsafe(suffix)}`;
}

function splitCanonicalUrl(canonicalUrl: string): {
  hostname: string;
  path: string;
  query?: string;
} {
  const schemeEnd = canonicalUrl.indexOf('://');
  const afterScheme = canonicalUrl.slice(schemeEnd + 3);
  const pathStart = afterScheme.indexOf('/');
  const hostname = pathStart < 0 ? afterScheme : afterScheme.slice(0, pathStart);
  const pathAndQuery = pathStart < 0 ? '/' : afterScheme.slice(pathStart);
  const queryIndex = pathAndQuery.indexOf('?');
  return {
    hostname,
    path: queryIndex < 0 ? pathAndQuery : pathAndQuery.slice(0, queryIndex),
    query: queryIndex < 0 ? undefined : pathAndQuery.slice(queryIndex + 1)
  };
}

export function safeBrowsingExpressions(input: string): string[] {
  const canonicalUrl = canonicalizeSafeBrowsingUrl(input);
  const { hostname, path, query } = splitCanonicalUrl(canonicalUrl);
  const hosts = [hostname];
  const isIpAddress = hostname.startsWith('[') || /^\d+\.\d+\.\d+\.\d+$/.test(hostname);
  if (!isIpAddress) {
    const components = hostname.split('.');
    const start = Math.max(0, components.length - 5);
    for (let index = start; index < components.length - 1; index += 1) {
      const suffix = components.slice(index).join('.');
      if (suffix !== hostname) hosts.push(suffix);
    }
  }

  const paths: string[] = [];
  if (query !== undefined) paths.push(`${path}?${query}`);
  paths.push(path, '/');
  const components = path.split('/').filter(Boolean);
  let prefix = '/';
  for (let index = 0; index < Math.min(4, Math.max(0, components.length - 1)); index += 1) {
    prefix += `${components[index]}/`;
    paths.push(prefix);
  }

  const expressions: string[] = [];
  const seen = new Set<string>();
  for (const host of hosts.slice(0, 5)) {
    for (const candidatePath of paths.slice(0, 6)) {
      const expression = `${host}${candidatePath}`;
      if (!seen.has(expression)) {
        seen.add(expression);
        expressions.push(expression);
      }
    }
  }
  return expressions.slice(0, 30);
}

export async function sha256(input: string): Promise<Uint8Array> {
  if (!globalThis.crypto?.subtle) {
    throw new Error('Web Crypto SHA-256 is unavailable.');
  }
  return new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', textEncoder.encode(input)));
}

export async function hashSafeBrowsingUrl(input: string): Promise<SafeBrowsingHash[]> {
  return Promise.all(
    safeBrowsingExpressions(input).map(async (expression) => {
      const fullHash = await sha256(expression);
      return { expression, fullHash, prefix: fullHash.slice(0, 4) };
    })
  );
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  for (let index = 0; index < left.length; index += 1) {
    if (left[index] !== right[index]) return false;
  }
  return true;
}

export function findBlockingMatch(
  localHashes: readonly SafeBrowsingHash[],
  details: readonly SafeBrowsingFullHash[]
): SafeBrowsingFullHash | undefined {
  return details.find(
    (detail) =>
      detail.fullHash.length === 32 &&
      BLOCKING_THREAT_TYPES.has(detail.threatType) &&
      !detail.attributes.includes('CANARY') &&
      localHashes.some((local) => equalBytes(local.fullHash, detail.fullHash))
  );
}
