import { readFileSync, writeFileSync } from 'node:fs';
import { mask } from '@shc/shared';
import { describe, expect, it } from 'vitest';
import { deriveSiteKey, hashPairingCode, hashSiteKey, normalizePairingCode, REPORTS_PATH, sha256Hex, signRequest, stringToSign } from '../src';

/**
 * Cross-language test vectors. The PHP plugin's tests read the same file, so both sides
 * must agree byte for byte. Regenerate after an intentional protocol change with
 * UPDATE_VECTORS=1 npx vitest run packages/companion
 */
const VECTORS = new URL('./vectors.json', import.meta.url);

function buildVectors() {
  const secret = 'test-only-secret-0123456789abcdef0123456789abcdef';
  const keys = ['0b7e5c9a-3f1d-4c2e-9a8b-6d5f4e3c2b1a', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'].map((keyId) => {
    const key = deriveSiteKey(secret, keyId);
    return { secret, keyId, key, keyHash: hashSiteKey(key) };
  });

  const bodies = ['{"schema":1}', '{"site":{"homeUrl":"https://café.example"},"note":"naïve ✓"}', ''];
  const signatures = bodies.map((body, i) => {
    const key = keys[i % keys.length]!.key;
    const req = { method: 'POST', path: REPORTS_PATH, timestamp: 1794400000 + i, nonce: `nonce-${'abcdef0123456789'.slice(i)}xyz`, body };
    return { key, ...req, bodySha256: sha256Hex(body), stringToSign: stringToSign(req), signature: signRequest(key, req) };
  });

  const pairing = [' abcde-fghjk ', 'ol1ab cdefg', 'ABCDEFGHJK', 'abcde-fghju', 'abc', 'abcde-fghjk-1'].map((input) => {
    const normalized = normalizePairingCode(input);
    return { input, normalized, hash: normalized ? hashPairingCode(normalized) : null };
  });

  const masks = ['shc-admin', 'ab', 'x', '', 'abc', 'averyverylongusername', 'josé', 's******n'].map((input) => ({ input, masked: mask(input) }));

  return { keys, signatures, pairing, mask: masks };
}

describe('protocol test vectors', () => {
  it('vectors.json matches the implementation', () => {
    const current = buildVectors();
    if (process.env.UPDATE_VECTORS === '1') writeFileSync(VECTORS, `${JSON.stringify(current, null, 2)}\n`);
    expect(JSON.parse(readFileSync(VECTORS, 'utf8'))).toEqual(current);
  });
});
