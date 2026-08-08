export const BASE62_ALPHABET = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
export const ENCODED_ID_LENGTH = 11;

const MAX_UINT64 = 1n << 64n;
const BASE = 62n;

export function generateIdBytes(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(8));
}

export function encodeId(idBytes: Uint8Array): string {
  if (idBytes.length !== 8) {
    throw new Error('ID must be exactly 8 bytes.');
  }

  let value = 0n;
  for (let index = idBytes.length - 1; index >= 0; index -= 1) {
    value = (value << 8n) | BigInt(idBytes[index]);
  }

  let encoded = '';
  do {
    encoded = BASE62_ALPHABET[Number(value % BASE)] + encoded;
    value /= BASE;
  } while (value > 0n);

  return encoded.padStart(ENCODED_ID_LENGTH, '0');
}

export function decodeId(encoded: string): Uint8Array {
  if (encoded.length !== ENCODED_ID_LENGTH) {
    throw new Error('Fragment ID must be exactly 11 characters.');
  }

  let value = 0n;
  for (const character of encoded) {
    const digit = BASE62_ALPHABET.indexOf(character);
    if (digit < 0) {
      throw new Error('Fragment ID contains a non-Base62 character.');
    }
    value = value * BASE + BigInt(digit);
  }

  if (value >= MAX_UINT64) {
    throw new Error('Fragment ID is outside the unsigned 64-bit range.');
  }

  const decoded = new Uint8Array(8);
  for (let index = 0; index < decoded.length; index += 1) {
    decoded[index] = Number(value & 0xffn);
    value >>= 8n;
  }

  if (encodeId(decoded) !== encoded) {
    throw new Error('Fragment ID is not canonically encoded.');
  }
  return decoded;
}

export function parseFragment(fragment: string = globalThis.location?.hash ?? ''): Uint8Array {
  if (!/^#[0-9A-Za-z]{11}$/.test(fragment)) {
    throw new Error('Invalid SecURL fragment.');
  }
  return decodeId(fragment.slice(1));
}
