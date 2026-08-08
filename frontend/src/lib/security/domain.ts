const DOT_EQUIVALENTS = /[\u3002\uff0e\uff61]/g;
const ASCII_DOMAIN_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const CANONICAL_IPV4 = /^\d+\.\d+\.\d+\.\d+$/;

export function normalizeServiceDomain(input: string): string {
  if (input === '' || input.trim() !== input || /[/\\@?#]/.test(input)) {
    throw new Error('Service domain is invalid.');
  }
  let candidate = input.replace(DOT_EQUIVALENTS, '.').replace(/\.+$/, '');
  if (candidate === '' || (candidate.includes(':') && !/^\[[0-9a-f:.]+\]$/i.test(candidate))) {
    throw new Error('Service domain is invalid.');
  }

  let normalized: string;
  try {
    normalized = new URL(`https://${candidate}/`).hostname.toLowerCase().replace(/\.+$/, '');
  } catch {
    throw new Error('Service domain is invalid.');
  }
  if (normalized === '') {
    throw new Error('Service domain is invalid.');
  }
  if (normalized.startsWith('[') && normalized.endsWith(']')) {
    return normalized;
  }
  if (CANONICAL_IPV4.test(normalized) || normalized === 'localhost') {
    return normalized;
  }
  if (normalized.length > 253) {
    throw new Error('Service domain is too long.');
  }
  const labels = normalized.split('.');
  if (labels.some((label) => !ASCII_DOMAIN_LABEL.test(label))) {
    throw new Error('Service domain contains an invalid DNS label.');
  }

  const canonical = new URL(`https://${normalized}/`).hostname.toLowerCase().replace(/\.+$/, '');
  if (canonical !== normalized) {
    throw new Error('Service domain is not canonically encoded.');
  }
  return normalized;
}
