/**
 * Turns user input ("https://www.Example.com/blog", "bücher.de") into the bare, lower-case,
 * punycode hostname we store and scan. Uses only the WHATWG URL parser, so it runs the
 * same in Node and in the browser.
 */
export type DomainResult = { ok: true; domain: string } | { ok: false; reason: string };

/** Suffixes that never point at a public website. */
const RESERVED_SUFFIXES = ['localhost', 'local', 'internal', 'intranet', 'lan', 'home.arpa', 'invalid', 'example', 'onion', 'test', 'corp', 'private'];

const LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const fail = (reason: string): DomainResult => ({ ok: false, reason });

export function normaliseDomain(input: string, options: { allow?: readonly string[] } = {}): DomainResult {
  const raw = input.trim();
  if (!raw) return fail('Enter your site address, for example example.com');
  if (raw.length > 2048) return fail('That address is too long');

  const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(raw) ? raw : `http://${raw}`;
  let url: URL;
  try {
    url = new URL(withScheme);
  } catch {
    return fail("That doesn't look like a valid domain");
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') return fail('Only http and https sites are supported');
  if (url.username || url.password) return fail('Remove the username and password from the address');
  if (url.port) return fail('Sites on non-standard ports are not supported');

  const host = url.hostname.toLowerCase().replace(/\.$/, '');
  if (host.startsWith('[') || /^\d{1,3}(?:\.\d{1,3}){3}$/.test(host)) {
    return fail('Enter a domain name rather than an IP address');
  }
  if (options.allow?.includes(host)) return { ok: true, domain: host };

  if (host.length > 253) return fail('That domain is too long');
  const labels = host.split('.');
  if (labels.length < 2) return fail('Enter a full domain, for example example.com');
  if (!labels.every((l) => LABEL.test(l))) return fail("That doesn't look like a valid domain");
  if (/^\d+$/.test(labels[labels.length - 1]!)) return fail("That doesn't look like a valid domain");
  if (RESERVED_SUFFIXES.some((s) => host === s || host.endsWith(`.${s}`))) {
    return fail('That domain is reserved for private networks and cannot be scanned');
  }
  return { ok: true, domain: host };
}
