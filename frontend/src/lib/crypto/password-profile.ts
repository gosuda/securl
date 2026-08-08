export const ARGON2ID_V1 = Object.freeze({
  version: 0x13,
  m: 65536,
  t: 3,
  p: 1,
  dkLen: 32
});

export const PASSWORD_DERIVATION_UNAVAILABLE =
  'This device cannot derive the password key safely.';
