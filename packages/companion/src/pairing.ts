import { createHash, randomInt } from 'node:crypto';

/** Crockford base32: no I, L, O or U, so codes survive being read aloud or retyped. */
const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
const LENGTH = 10;

/** A fresh one-time code, formatted for display: "ABCDE-FGHJK" (50 bits). */
export function generatePairingCode(): string {
  let code = '';
  for (let i = 0; i < LENGTH; i++) code += ALPHABET[randomInt(ALPHABET.length)];
  return `${code.slice(0, 5)}-${code.slice(5)}`;
}

/** What the admin typed, reduced to the canonical ten characters, or null if it can't be a code. */
export function normalizePairingCode(input: string): string | null {
  const code = input
    .toUpperCase()
    .replace(/[\s-]/g, '')
    .replace(/O/g, '0')
    .replace(/[IL]/g, '1');
  return /^[0-9A-HJKMNP-TV-Z]{10}$/.test(code) ? code : null;
}

/** Only this hash is stored; the code itself is shown once. */
export function hashPairingCode(normalized: string): string {
  return createHash('sha256').update(`shc-pairing-code/v1:${normalized}`).digest('hex');
}
