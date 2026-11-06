import http from 'node:http';
import https from 'node:https';
import { isIP, type LookupFunction } from 'node:net';
import { systemHostResolver, type HostResolver, type ResolvedAddress } from './dns';
import { NetError, toNetError } from './errors';
import { isPublicAddress } from './ip-policy';

export type RedirectPolicy = 'none' | 'same-host' | 'same-site';

export interface NetPolicy {
  /** Honest User-Agent naming the product. */
  userAgent: string;
  /** Hostnames allowed to resolve to private addresses. Development and tests only. */
  allowPrivateHosts?: Iterable<string>;
  /** Destination ports we will connect to. Defaults to 80 and 443. */
  allowedPorts?: Iterable<number>;
  resolveHost?: HostResolver;
}

export interface FetchOptions {
  method?: 'GET' | 'HEAD';
  headers?: Record<string, string>;
  /** Total time budget across all redirects. */
  timeoutMs?: number;
  /** Stop reading the body after this many bytes. */
  maxBytes?: number;
  redirect?: RedirectPolicy;
  maxRedirects?: number;
  rejectUnauthorized?: boolean;
}

export interface SafeResponse {
  url: string;
  status: number;
  headers: http.IncomingHttpHeaders;
  body: Buffer;
  truncated: boolean;
  remoteAddress: string;
  redirects: string[];
}

const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

function bareHost(hostname: string): string {
  return hostname.replace(/^\[|\]$/g, '').toLowerCase();
}

function redirectAllowed(origin: string, next: string, policy: RedirectPolicy): boolean {
  if (policy === 'none') return false;
  if (next === origin) return true;
  if (policy === 'same-site') return next === `www.${origin}` || origin === `www.${next}`;
  return false;
}

/**
 * HTTP client for talking to user-supplied hosts without becoming an SSRF proxy.
 *
 * - Only http/https on allowed ports; no credentials in URLs.
 * - Resolves DNS itself and refuses if ANY address is private or reserved, then pins the
 *   connection to the vetted address so a second DNS answer cannot redirect it (rebinding).
 * - Follows redirects only when asked, re-checking every hop.
 * - Hard limits on total time and response size.
 */
export class SafeFetcher {
  private readonly allowPrivate: Set<string>;
  private readonly ports: Set<number>;
  private readonly resolveHost: HostResolver;

  constructor(private readonly policy: NetPolicy) {
    this.allowPrivate = new Set([...(policy.allowPrivateHosts ?? [])].map((h) => h.toLowerCase()));
    this.ports = new Set(policy.allowedPorts ?? [80, 443]);
    this.resolveHost = policy.resolveHost ?? systemHostResolver;
  }

  async fetch(input: string, options: FetchOptions = {}): Promise<SafeResponse> {
    const redirectPolicy = options.redirect ?? 'none';
    const maxRedirects = options.maxRedirects ?? 3;
    const deadline = Date.now() + (options.timeoutMs ?? 10_000);

    let url = this.parse(input);
    const origin = bareHost(url.hostname);
    const redirects: string[] = [];

    for (;;) {
      const res = await this.request(url, options, deadline);
      const location = res.headers.location;
      if (redirectPolicy === 'none' || !REDIRECT_STATUSES.has(res.status) || !location) {
        return { ...res, redirects };
      }
      if (redirects.length >= maxRedirects) {
        throw new NetError('too_many_redirects', 'Too many redirects', url.toString());
      }
      let next: URL;
      try {
        next = this.parse(new URL(location, url).toString());
      } catch (err) {
        throw err instanceof NetError ? new NetError('redirect_blocked', `Redirect target refused: ${err.message}`, location) : err;
      }
      if (!redirectAllowed(origin, bareHost(next.hostname), redirectPolicy)) {
        throw new NetError('redirect_blocked', `Redirected to a different host (${bareHost(next.hostname)})`, next.toString());
      }
      redirects.push(next.toString());
      url = next;
    }
  }

  private parse(input: string): URL {
    let url: URL;
    try {
      url = new URL(input);
    } catch {
      throw new NetError('invalid_url', 'Invalid URL', input);
    }
    if (url.protocol !== 'http:' && url.protocol !== 'https:') {
      throw new NetError('blocked_scheme', `Scheme ${url.protocol} is not allowed`, input);
    }
    if (url.username || url.password) throw new NetError('invalid_url', 'Credentials in URLs are not allowed', input);
    const port = url.port ? Number(url.port) : url.protocol === 'https:' ? 443 : 80;
    if (!this.ports.has(port)) throw new NetError('blocked_port', `Port ${port} is not allowed`, input);
    return url;
  }

  /** Resolves and vets the destination. Every resolved address must be public. */
  async resolve(hostname: string): Promise<ResolvedAddress> {
    const host = bareHost(hostname);
    const literal = isIP(host);
    if (literal) {
      if (!isPublicAddress(host) && !this.allowPrivate.has(host)) {
        throw new NetError('blocked_address', `${host} is a private or reserved address`);
      }
      return { address: host, family: literal === 6 ? 6 : 4 };
    }

    let addresses: ResolvedAddress[];
    try {
      addresses = await this.resolveHost(host);
    } catch {
      throw new NetError('dns_failed', `Could not resolve ${host}`);
    }
    if (addresses.length === 0) throw new NetError('dns_failed', `Could not resolve ${host}`);

    if (!this.allowPrivate.has(host)) {
      const unsafe = addresses.find((a) => !isPublicAddress(a.address));
      if (unsafe) throw new NetError('blocked_address', `${host} resolves to a private or reserved address`);
    }
    return addresses[0]!;
  }

  private async request(url: URL, options: FetchOptions, deadline: number): Promise<Omit<SafeResponse, 'redirects'>> {
    const target = await this.resolve(url.hostname);
    const remaining = deadline - Date.now();
    if (remaining <= 0) throw new NetError('timeout', 'The request timed out', url.toString());

    const method = options.method ?? 'GET';
    const maxBytes = options.maxBytes ?? 256 * 1024;
    const host = bareHost(url.hostname);
    const isHttps = url.protocol === 'https:';

    // Pin the socket to the address we vetted, whatever DNS says next.
    const lookup = ((_hostname: string, opts: { all?: boolean } | undefined, callback: (...args: unknown[]) => void) => {
      if (opts?.all) callback(null, [{ address: target.address, family: target.family }]);
      else callback(null, target.address, target.family);
    }) as unknown as LookupFunction;

    const headers: Record<string, string> = { accept: '*/*', ...options.headers, 'user-agent': this.policy.userAgent };
    delete headers.host;

    return new Promise((resolve, reject) => {
      let settled = false;
      const done = (fn: () => void) => {
        if (!settled) {
          settled = true;
          fn();
        }
      };

      const requestOptions: https.RequestOptions = {
        protocol: url.protocol,
        hostname: host,
        port: url.port || undefined,
        path: `${url.pathname}${url.search}`,
        method,
        headers,
        lookup,
        agent: false,
        signal: AbortSignal.timeout(remaining),
      };
      if (isHttps) {
        if (!isIP(host)) requestOptions.servername = host;
        requestOptions.rejectUnauthorized = options.rejectUnauthorized ?? true;
      }

      const req = (isHttps ? https : http).request(requestOptions, (res) => {
        const chunks: Buffer[] = [];
        let size = 0;
        let truncated = false;
        const finish = () =>
          done(() =>
            resolve({
              url: url.toString(),
              status: res.statusCode ?? 0,
              headers: res.headers,
              body: Buffer.concat(chunks),
              truncated,
              remoteAddress: target.address,
            }),
          );

        if (method === 'HEAD') {
          res.resume();
          res.on('end', finish);
          return;
        }
        res.on('data', (chunk: Buffer) => {
          if (truncated) return;
          const room = maxBytes - size;
          if (chunk.length >= room) {
            chunks.push(chunk.subarray(0, room));
            size = maxBytes;
            truncated = chunk.length > room;
            if (truncated) {
              finish();
              req.destroy();
            }
            return;
          }
          chunks.push(chunk);
          size += chunk.length;
        });
        res.on('end', finish);
        res.on('error', (err) => done(() => reject(toNetError(err, url.toString()))));
      });

      req.on('error', (err) => done(() => reject(toNetError(err, url.toString()))));
      req.end();
    });
  }
}
