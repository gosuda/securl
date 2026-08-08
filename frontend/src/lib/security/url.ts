const textEncoder = new TextEncoder();
const MAX_URL_BYTES = 4096;
const ASCII_EDGE_WHITESPACE = /^[\t\n\f\r ]+|[\t\n\f\r ]+$/g;
const CONTROL_CHARACTER = /[\u0000-\u001f\u007f]/;
const EXPLICIT_SCHEME = /^([a-z][a-z0-9+.-]*):/i;
const NUMERIC_PORT = /^\d+(?:[/?#]|$)/;

function withDefaultProtocol(input: string): string {
  if (input.startsWith('//')) return `https:${input}`;
  const scheme = input.match(EXPLICIT_SCHEME);
  if (!scheme) return `https://${input}`;
  const hostWithPort = scheme[1].includes('.') && NUMERIC_PORT.test(input.slice(scheme[0].length));
  return hostWithPort ? `https://${input}` : input;
}

function parseIPv4(hostname: string): number[] | undefined {
  if (!/^\d+\.\d+\.\d+\.\d+$/.test(hostname)) return undefined;
  const octets = hostname.split('.').map(Number);
  if (octets.some((octet) => octet < 0 || octet > 255)) return undefined;
  return octets;
}

function isBlockedIPv4(octets: number[]): boolean {
  const [a, b] = octets;
  return (
    a === 0 ||
    a === 10 ||
    a === 127 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 198 && (b === 18 || b === 19)) ||
    (a >= 224 && a <= 239) ||
    a >= 240
  );
}

function parseIPv6Part(part: string): number[] | undefined {
  if (part === '') return [];
  const groups: number[] = [];
  for (const token of part.split(':')) {
    const ipv4 = parseIPv4(token);
    if (ipv4) {
      groups.push((ipv4[0] << 8) | ipv4[1], (ipv4[2] << 8) | ipv4[3]);
      continue;
    }
    if (!/^[0-9a-f]{1,4}$/i.test(token)) return undefined;
    groups.push(Number.parseInt(token, 16));
  }
  return groups;
}

function parseIPv6(hostname: string): number[] | undefined {
  const unbracketed = hostname.startsWith('[') && hostname.endsWith(']')
    ? hostname.slice(1, -1)
    : hostname;
  if (!unbracketed.includes(':') || unbracketed.includes('%')) return undefined;
  const halves = unbracketed.split('::');
  if (halves.length > 2) return undefined;
  const left = parseIPv6Part(halves[0]);
  const right = parseIPv6Part(halves[1] ?? '');
  if (!left || !right) return undefined;

  if (halves.length === 1) {
    return left.length === 8 ? left : undefined;
  }
  const zeroCount = 8 - left.length - right.length;
  if (zeroCount < 1) return undefined;
  return [...left, ...new Array<number>(zeroCount).fill(0), ...right];
}

function isBlockedIPv6(groups: number[]): boolean {
  const allZero = groups.every((group) => group === 0);
  const loopback = groups.slice(0, 7).every((group) => group === 0) && groups[7] === 1;
  const uniqueLocal = (groups[0] & 0xfe00) === 0xfc00;
  const linkLocal = (groups[0] & 0xffc0) === 0xfe80;
  const siteLocal = (groups[0] & 0xffc0) === 0xfec0;
  const multicast = (groups[0] & 0xff00) === 0xff00;
  const ipv4Mapped = groups.slice(0, 5).every((group) => group === 0) && groups[5] === 0xffff;
  const ipv4Compatible = groups.slice(0, 6).every((group) => group === 0);
  if (ipv4Mapped || ipv4Compatible) {
    const embedded = [groups[6] >> 8, groups[6] & 0xff, groups[7] >> 8, groups[7] & 0xff];
    if (isBlockedIPv4(embedded)) return true;
  }
  return allZero || loopback || uniqueLocal || linkLocal || siteLocal || multicast;
}

export function validateDestination(input: string): URL {
  const trimmed = input.replace(ASCII_EDGE_WHITESPACE, '');
  if (trimmed === '') {
    throw new Error('Destination URL must be between 1 and 4096 UTF-8 bytes.');
  }
  if (CONTROL_CHARACTER.test(trimmed)) {
    throw new Error('Destination URL contains a control character.');
  }
  const canonicalInput = withDefaultProtocol(trimmed);
  if (textEncoder.encode(canonicalInput).length > MAX_URL_BYTES) {
    throw new Error('Destination URL must be between 1 and 4096 UTF-8 bytes.');
  }

  let destination: URL;
  try {
    destination = new URL(canonicalInput);
  } catch {
    throw new Error('Destination URL is invalid.');
  }
  if (textEncoder.encode(destination.href).length > MAX_URL_BYTES) {
    throw new Error('Destination URL must be between 1 and 4096 UTF-8 bytes.');
  }
  if (destination.protocol !== 'http:' && destination.protocol !== 'https:') {
    throw new Error('Destination URL must use HTTP or HTTPS.');
  }
  if (destination.username !== '' || destination.password !== '') {
    throw new Error('Destination URL must not contain credentials.');
  }

  const hostname = destination.hostname.toLowerCase();
  const policyHostname = hostname.replace(/\.+$/, '');
  if (
    policyHostname === '' ||
    policyHostname === 'localhost' ||
    policyHostname.endsWith('.localhost') ||
    policyHostname.endsWith('.local')
  ) {
    throw new Error('Destination hostname is not publicly routable.');
  }
  const ipv4 = parseIPv4(policyHostname);
  if (ipv4 && isBlockedIPv4(ipv4)) {
    throw new Error('Destination IPv4 address is not publicly routable.');
  }
  const ipv6 = parseIPv6(policyHostname);
  if (ipv6 && isBlockedIPv6(ipv6)) {
    throw new Error('Destination IPv6 address is not publicly routable.');
  }

  return destination;
}
