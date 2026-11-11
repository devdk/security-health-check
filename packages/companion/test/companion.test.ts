import { describe, expect, it } from 'vitest';
import {
  deriveSiteKey,
  generatePairingCode,
  hashPairingCode,
  isFresh,
  normalizePairingCode,
  parseInsideReport,
  readSignedHeaders,
  REPORTS_PATH,
  signRequest,
  verifySignature,
} from '../src';
import { sampleInsideReport } from '../src/testing';

const keyId = '0b7e5c9a-3f1d-4c2e-9a8b-6d5f4e3c2b1a';
const key = deriveSiteKey('secret-for-tests-only-0123456789abcdef', keyId);
const req = { method: 'POST', path: REPORTS_PATH, timestamp: 1_794_400_000, nonce: 'n0nce-abcdefghijkl', body: '{"schema":1}' };
const sampleReport = sampleInsideReport();

describe('pairing codes', () => {
  it('generates codes that normalise to themselves', () => {
    for (let i = 0; i < 50; i++) {
      const code = generatePairingCode();
      expect(code).toMatch(/^[0-9A-HJKMNP-TV-Z]{5}-[0-9A-HJKMNP-TV-Z]{5}$/);
      expect(normalizePairingCode(code)).toBe(code.replace('-', ''));
    }
  });

  it('forgives case, spaces, hyphens and look-alike letters', () => {
    expect(normalizePairingCode(' abcde-fghjk ')).toBe('ABCDEFGHJK');
    expect(normalizePairingCode('ol1ab cdefg')).toBe('011ABCDEFG');
  });

  it('rejects anything that cannot be a code', () => {
    for (const bad of ['', 'abc', 'ABCDE-FGHJU', 'ABCDE-FGHJK1', 'ABCDE_FGHJK']) expect(normalizePairingCode(bad)).toBeNull();
  });

  it('hashes deterministically and differently per code', () => {
    expect(hashPairingCode('ABCDEFGHJK')).toBe(hashPairingCode('ABCDEFGHJK'));
    expect(hashPairingCode('ABCDEFGHJK')).not.toBe(hashPairingCode('ABCDEFGHJM'));
  });
});

describe('site keys', () => {
  it('derives a stable 256-bit key per key id and secret', () => {
    expect(key).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(deriveSiteKey('secret-for-tests-only-0123456789abcdef', keyId)).toBe(key);
    expect(deriveSiteKey('another-secret-entirely-0123456789abcd', keyId)).not.toBe(key);
    expect(deriveSiteKey('secret-for-tests-only-0123456789abcdef', 'f47ac10b-58cc-4372-a567-0e02b2c3d479')).not.toBe(key);
  });
});

describe('request signing', () => {
  const signature = signRequest(key, req);

  it('verifies its own signature', () => {
    expect(signature).toMatch(/^v1=[0-9a-f]{64}$/);
    expect(verifySignature(key, req, signature)).toBe(true);
  });

  it('fails when anything signed changes', () => {
    const variants = [
      { ...req, body: '{"schema":2}' },
      { ...req, timestamp: req.timestamp + 1 },
      { ...req, nonce: 'n0nce-abcdefghijkm' },
      { ...req, path: '/api/plugin/pair' },
      { ...req, method: 'PUT' },
    ];
    for (const v of variants) expect(verifySignature(key, v, signature)).toBe(false);
    expect(verifySignature(deriveSiteKey('another-secret-entirely-0123456789abcd', keyId), req, signature)).toBe(false);
  });

  it('rejects malformed signature headers without throwing', () => {
    for (const bad of ['', 'v1=', 'v2=' + 'a'.repeat(64), signature.toUpperCase(), signature + '0']) expect(verifySignature(key, req, bad)).toBe(false);
  });

  it('accepts timestamps within five minutes either way', () => {
    const now = new Date(req.timestamp * 1000);
    expect(isFresh(req.timestamp - 300, now)).toBe(true);
    expect(isFresh(req.timestamp + 300, now)).toBe(true);
    expect(isFresh(req.timestamp - 301, now)).toBe(false);
    expect(isFresh(req.timestamp + 301, now)).toBe(false);
  });
});

describe('signed headers', () => {
  const good = {
    'x-shc-key-id': keyId,
    'x-shc-timestamp': String(req.timestamp),
    'x-shc-nonce': req.nonce,
    'x-shc-signature': signRequest(key, req),
  };

  it('reads well-formed headers', () => {
    expect(readSignedHeaders(good)).toEqual({ keyId, timestamp: req.timestamp, nonce: req.nonce, signature: good['x-shc-signature'] });
  });

  it('refuses missing, repeated or malformed headers', () => {
    for (const [name, value] of [
      ['x-shc-key-id', undefined],
      ['x-shc-key-id', 'not-a-uuid'],
      ['x-shc-timestamp', '-1'],
      ['x-shc-timestamp', '1.5'],
      ['x-shc-nonce', 'short'],
      ['x-shc-nonce', 'has spaces in it ok?'],
      ['x-shc-signature', 'sha256=abc'],
      ['x-shc-signature', [good['x-shc-signature'], good['x-shc-signature']]],
    ] as const) {
      expect(readSignedHeaders({ ...good, [name]: value as string | string[] | undefined }), `${name}=${String(value)}`).toBeNull();
    }
  });
});

describe('inside report schema', () => {
  it('accepts a complete report', () => {
    expect(parseInsideReport(sampleReport)).toEqual({ ok: true, report: sampleReport });
  });

  it('refuses unknown fields, so nothing unexpected is stored', () => {
    const result = parseInsideReport({ ...sampleReport, passwords: ['x'] });
    expect(result.ok).toBe(false);
  });

  it('refuses other schema versions and missing sections', () => {
    expect(parseInsideReport({ ...sampleReport, schema: 2 }).ok).toBe(false);
    const { php: _php, ...withoutPhp } = sampleReport;
    expect(parseInsideReport(withoutPhp).ok).toBe(false);
  });

  it('refuses absolute paths, control characters and oversized lists', () => {
    const withPath = (path: string) => ({ ...sampleReport, uploadsPhp: { ...sampleReport.uploadsPhp, files: [{ path, size: 10, modifiedAt: '2026-11-10T10:00:00Z' }] } });
    expect(parseInsideReport(withPath('2026/11/shell.php')).ok).toBe(true);
    expect(parseInsideReport(withPath('/var/www/html/wp-content/uploads/shell.php')).ok).toBe(false);
    expect(parseInsideReport(withPath('2026/11/she\nll.php')).ok).toBe(false);
    const many = Array.from({ length: 101 }, (_, i) => `wp-includes/file-${i}.php`);
    expect(parseInsideReport({ ...sampleReport, coreIntegrity: { ...sampleReport.coreIntegrity, modified: many } }).ok).toBe(false);
  });

  it('explains what is wrong', () => {
    const result = parseInsideReport({ ...sampleReport, wordpress: { version: '', locale: 'en_US' } });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.errors.join(' ')).toContain('/wordpress/version');
  });
});
