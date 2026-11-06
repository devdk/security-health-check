import type { VerifyMethod } from '@shc/shared';
import type { TxtResolver } from './dns';
import { NetError } from './errors';
import type { SafeFetcher } from './safe-fetch';

export const VERIFY_DNS_LABEL = '_shc-verify';

/** The part of SafeFetcher ownership checks need; lets tests supply recorded responses. */
export type Fetcher = Pick<SafeFetcher, 'fetch'>;

export interface OwnershipInstructions {
  dns: { name: string; type: 'TXT'; value: string };
  file: { filename: string; url: string; content: string };
}

export function ownershipInstructions(domain: string, token: string): OwnershipInstructions {
  const value = `shc-verify=${token}`;
  const filename = `shc-verify-${token}.txt`;
  return {
    dns: { name: `${VERIFY_DNS_LABEL}.${domain}`, type: 'TXT', value },
    file: { filename, url: `https://${domain}/${filename}`, content: value },
  };
}

export type OwnershipResult = { ok: true; detail: string } | { ok: false; reason: string };

export interface OwnershipChecker {
  check(method: VerifyMethod, domain: string, token: string): Promise<OwnershipResult>;
}

/**
 * Looks for `shc-verify=<token>` at `_shc-verify.<domain>` and, as a fallback, on the
 * domain itself (some DNS hosts make sub-labels awkward).
 */
export async function checkDnsOwnership(domain: string, token: string, resolveTxt: TxtResolver): Promise<OwnershipResult> {
  const { dns } = ownershipInstructions(domain, token);
  let mismatched = false;

  for (const name of [dns.name, domain]) {
    let records: string[];
    try {
      records = await resolveTxt(name);
    } catch (err) {
      if (err instanceof NetError && err.code === 'timeout') {
        return { ok: false, reason: `DNS lookup for ${name} timed out. Please try again in a minute.` };
      }
      records = [];
    }
    const values = records.map((r) => r.trim().replace(/^"|"$/g, ''));
    if (values.includes(dns.value)) return { ok: true, detail: `TXT record found at ${name}` };
    if (values.some((v) => v.startsWith('shc-verify='))) mismatched = true;
  }

  return {
    ok: false,
    reason: mismatched
      ? `We found a shc-verify TXT record, but its value doesn't match. Copy the whole value again: ${dns.value}`
      : `No matching TXT record at ${dns.name} yet. New DNS records can take a few minutes, occasionally hours, to appear.`,
  };
}

function describe(err: NetError, domain: string): string {
  switch (err.code) {
    case 'blocked_address':
      return `${domain} points to a private or reserved network address, so we can't check it.`;
    case 'dns_failed':
      return `We couldn't find ${domain} in DNS. Check the domain is spelled correctly.`;
    case 'timeout':
      return 'Your site took too long to respond. Please try again.';
    case 'tls_failed':
      return "Your site's HTTPS certificate isn't valid, and it isn't reachable over plain HTTP either.";
    case 'redirect_blocked':
      return `Your site redirected the request to another domain. The file must be served from ${domain} itself.`;
    case 'too_many_redirects':
      return 'Your site redirected the request too many times.';
    default:
      return "We couldn't connect to your site. Check that it's online.";
  }
}

/**
 * Fetches `/<filename>` from the site root and requires the body to equal the expected
 * value exactly. Exact matching defeats "soft 404" pages that echo the requested path.
 * Plain HTTP is tried only when HTTPS can't be reached at all.
 */
export async function checkFileOwnership(domain: string, token: string, fetcher: Fetcher): Promise<OwnershipResult> {
  const { file } = ownershipInstructions(domain, token);
  const urls = [`https://${domain}/${file.filename}`, `http://${domain}/${file.filename}`];

  for (const [index, url] of urls.entries()) {
    try {
      const res = await fetcher.fetch(url, { redirect: 'same-site', maxRedirects: 3, maxBytes: 1024, timeoutMs: 8000 });
      if (res.status !== 200) {
        return {
          ok: false,
          reason: `${res.url} returned HTTP ${res.status}. Upload the file to your site's root folder (the one containing wp-config.php).`,
        };
      }
      const body = res.body.toString('utf8').replace(/^﻿/, '').trim();
      if (body === file.content) return { ok: true, detail: `Verification file found at ${res.url}` };
      return { ok: false, reason: `We found ${res.url}, but its contents don't match. It must contain exactly: ${file.content}` };
    } catch (err) {
      if (!(err instanceof NetError)) throw err;
      const httpsUnreachable = index === 0 && (err.code === 'connect_failed' || err.code === 'tls_failed' || err.code === 'timeout');
      if (httpsUnreachable) continue;
      return { ok: false, reason: describe(err, domain) };
    }
  }
  return { ok: false, reason: describe(new NetError('connect_failed', 'unreachable'), domain) };
}

export class OwnershipVerifier implements OwnershipChecker {
  constructor(private readonly deps: { fetcher: Fetcher; resolveTxt: TxtResolver }) {}

  check(method: VerifyMethod, domain: string, token: string): Promise<OwnershipResult> {
    return method === 'dns_txt'
      ? checkDnsOwnership(domain, token, this.deps.resolveTxt)
      : checkFileOwnership(domain, token, this.deps.fetcher);
  }
}
