import { describe, expect, it } from 'vitest';
import { NetError } from '../src/errors';
import { checkDnsOwnership, checkFileOwnership, ownershipInstructions, type Fetcher } from '../src/ownership';
import type { SafeResponse } from '../src/safe-fetch';

const DOMAIN = 'example.com';
const TOKEN = '0123456789abcdef0123456789abcdef';
const VALUE = `shc-verify=${TOKEN}`;

describe('ownershipInstructions', () => {
  it('describes the DNS record and the file', () => {
    expect(ownershipInstructions(DOMAIN, TOKEN)).toEqual({
      dns: { name: '_shc-verify.example.com', type: 'TXT', value: VALUE },
      file: { filename: `shc-verify-${TOKEN}.txt`, url: `https://example.com/shc-verify-${TOKEN}.txt`, content: VALUE },
    });
  });
});

describe('checkDnsOwnership', () => {
  const txt = (table: Record<string, string[]>) => async (name: string) => table[name] ?? [];

  it('accepts the record on the _shc-verify label', async () => {
    const res = await checkDnsOwnership(DOMAIN, TOKEN, txt({ '_shc-verify.example.com': ['v=spf1 -all', VALUE] }));
    expect(res).toEqual({ ok: true, detail: 'TXT record found at _shc-verify.example.com' });
  });

  it('accepts the record on the domain itself, quoted or not', async () => {
    const res = await checkDnsOwnership(DOMAIN, TOKEN, txt({ 'example.com': [`"${VALUE}"`] }));
    expect(res.ok).toBe(true);
  });

  it('explains a mismatched value', async () => {
    const res = await checkDnsOwnership(DOMAIN, TOKEN, txt({ '_shc-verify.example.com': ['shc-verify=somethingelse'] }));
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toMatch(/doesn't match/);
  });

  it('rejects a record that only contains the token as a substring', async () => {
    const res = await checkDnsOwnership(DOMAIN, TOKEN, txt({ '_shc-verify.example.com': [`x${VALUE}x`] }));
    expect(res.ok).toBe(false);
  });

  it('explains a missing record', async () => {
    const res = await checkDnsOwnership(DOMAIN, TOKEN, txt({}));
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toMatch(/No matching TXT record at _shc-verify\.example\.com/);
  });

  it('reports DNS timeouts as retryable', async () => {
    const res = await checkDnsOwnership(DOMAIN, TOKEN, async () => {
      throw new NetError('timeout', 'slow');
    });
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toMatch(/timed out/);
  });
});

describe('checkFileOwnership', () => {
  type Reply = Partial<SafeResponse> | NetError;
  /** Recorded responses keyed by URL; records which URLs were requested. */
  function fakeFetcher(replies: Record<string, Reply>): Fetcher & { requested: string[] } {
    const requested: string[] = [];
    return {
      requested,
      async fetch(url: string) {
        requested.push(url);
        const reply = replies[url];
        if (!reply) throw new NetError('connect_failed', 'no route', url);
        if (reply instanceof NetError) throw reply;
        return { url, status: 200, headers: {}, body: Buffer.alloc(0), truncated: false, remoteAddress: '93.184.216.34', redirects: [], ...reply };
      },
    };
  }
  const httpsUrl = `https://example.com/shc-verify-${TOKEN}.txt`;
  const httpUrl = `http://example.com/shc-verify-${TOKEN}.txt`;

  it('accepts an exact match over https', async () => {
    const f = fakeFetcher({ [httpsUrl]: { body: Buffer.from(VALUE) } });
    expect((await checkFileOwnership(DOMAIN, TOKEN, f)).ok).toBe(true);
    expect(f.requested).toEqual([httpsUrl]);
  });

  it('tolerates a byte-order mark and trailing newline from text editors', async () => {
    const f = fakeFetcher({ [httpsUrl]: { body: Buffer.from(`﻿${VALUE}\r\n`) } });
    expect((await checkFileOwnership(DOMAIN, TOKEN, f)).ok).toBe(true);
  });

  it('rejects "soft 404" pages that merely echo the path', async () => {
    const page = `<html><body>Sorry, /shc-verify-${TOKEN}.txt was not found. ${VALUE}</body></html>`;
    const res = await checkFileOwnership(DOMAIN, TOKEN, fakeFetcher({ [httpsUrl]: { body: Buffer.from(page) } }));
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toMatch(/contents don't match/);
  });

  it('reports the HTTP status when the file is missing', async () => {
    const res = await checkFileOwnership(DOMAIN, TOKEN, fakeFetcher({ [httpsUrl]: { status: 404 } }));
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toMatch(/HTTP 404/);
  });

  it('falls back to plain http only when https is unreachable', async () => {
    const f = fakeFetcher({ [httpsUrl]: new NetError('tls_failed', 'bad cert'), [httpUrl]: { body: Buffer.from(VALUE) } });
    expect((await checkFileOwnership(DOMAIN, TOKEN, f)).ok).toBe(true);
    expect(f.requested).toEqual([httpsUrl, httpUrl]);
  });

  it('does not fall back to http after an https HTTP response', async () => {
    const f = fakeFetcher({ [httpsUrl]: { status: 403 }, [httpUrl]: { body: Buffer.from(VALUE) } });
    expect((await checkFileOwnership(DOMAIN, TOKEN, f)).ok).toBe(false);
    expect(f.requested).toEqual([httpsUrl]);
  });

  it('stops immediately on SSRF blocks and cross-domain redirects', async () => {
    const blocked = fakeFetcher({ [httpsUrl]: new NetError('blocked_address', 'private') });
    const res1 = await checkFileOwnership(DOMAIN, TOKEN, blocked);
    expect(res1.ok).toBe(false);
    if (!res1.ok) expect(res1.reason).toMatch(/private or reserved/);
    expect(blocked.requested).toHaveLength(1);

    const redirected = fakeFetcher({ [httpsUrl]: new NetError('redirect_blocked', 'elsewhere') });
    const res2 = await checkFileOwnership(DOMAIN, TOKEN, redirected);
    if (!res2.ok) expect(res2.reason).toMatch(/another domain/);
    expect(redirected.requested).toHaveLength(1);
  });

  it('explains when neither https nor http answers', async () => {
    const res = await checkFileOwnership(DOMAIN, TOKEN, fakeFetcher({}));
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toMatch(/couldn't connect/);
  });
});
