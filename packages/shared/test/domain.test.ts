import { describe, expect, it } from 'vitest';
import { normaliseDomain } from '../src/domain';
import { siteStatus } from '../src/index';

describe('normaliseDomain', () => {
  it.each([
    ['example.com', 'example.com'],
    ['  Example.COM  ', 'example.com'],
    ['https://www.example.com/blog/?p=1#x', 'www.example.com'],
    ['http://shop.example.co.uk', 'shop.example.co.uk'],
    ['example.com.', 'example.com'],
    ['https://example.com:443', 'example.com'],
    ['bücher.de', 'xn--bcher-kva.de'],
    ['xn--bcher-kva.de', 'xn--bcher-kva.de'],
  ])('%s -> %s', (input, expected) => {
    expect(normaliseDomain(input)).toEqual({ ok: true, domain: expected });
  });

  it.each([
    ['', /Enter your site address/],
    ['localhost', /full domain/],
    ['192.168.1.10', /IP address/],
    ['http://127.1', /IP address/],
    ['http://0x7f.1/', /IP address/],
    ['[::1]', /IP address/],
    ['example.com:8080', /non-standard ports/],
    ['ftp://example.com', /http and https/],
    ['https://user:pw@example.com', /username and password/],
    ['intranet.local', /reserved/],
    ['app.localhost', /reserved/],
    ['wp.internal', /reserved/],
    ['site.test', /reserved/],
    ['exa mple.com', /valid domain/],
    ['-bad.example.com', /valid domain/],
    ['ex_ample.com', /valid domain/],
    ['example.123', /valid domain/],
  ])('rejects %s', (input, reason) => {
    const res = normaliseDomain(input);
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toMatch(reason);
  });

  it('lets explicitly allowed development hosts through', () => {
    expect(normaliseDomain('wordpress.test', { allow: ['wordpress.test'] })).toEqual({ ok: true, domain: 'wordpress.test' });
  });
});

describe('siteStatus', () => {
  const now = Date.parse('2026-11-06T12:00:00Z');
  it('is unverified without a verification date', () => {
    expect(siteStatus(null, now)).toBe('unverified');
  });
  it('is verified within 24 hours and stale after', () => {
    expect(siteStatus(new Date(now - 23 * 3600_000), now)).toBe('verified');
    expect(siteStatus(new Date(now - 25 * 3600_000), now)).toBe('stale');
  });
});
