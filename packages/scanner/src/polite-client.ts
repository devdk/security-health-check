import type { Fetcher, SafeResponse } from '@shc/net';
import type { RateLimiter } from './rate-limit';

export class BudgetExhaustedError extends Error {
  constructor(limit: number) {
    super(`Scan request limit of ${limit} reached`);
    this.name = 'BudgetExhaustedError';
  }
}

export class OutOfScopeError extends Error {
  constructor(url: string) {
    super(`Refusing to request ${url}: outside the verified site`);
    this.name = 'OutOfScopeError';
  }
}

export interface PoliteRequestOptions {
  method?: 'GET' | 'HEAD';
  maxBytes?: number;
  timeoutMs?: number;
  /** Follow redirects that stay on the verified site. Each hop counts as a request. */
  followRedirects?: boolean;
}

export interface PoliteResponse extends SafeResponse {
  /** True when a redirect pointed off the verified site and was not followed. */
  redirectedOffSite: boolean;
}

interface SharedState {
  readonly fetcher: Fetcher;
  readonly limiter: RateLimiter;
  readonly maxRequests: number;
  readonly scope: Set<string>;
  readonly rateKey: string;
  readonly signal?: AbortSignal;
  used: number;
  readonly perModule: Map<string, number>;
  readonly cache: Map<string, Promise<PoliteResponse>>;
}

const REDIRECTS = new Set([301, 302, 303, 307, 308]);
const MAX_HOPS = 3;

/**
 * The only way a check module may talk to a site. It enforces the product's scanning
 * rules in one place:
 * - only the verified domain (and its www/apex twin) can be contacted;
 * - every request, including each redirect hop, waits for the per-target rate limiter;
 * - a hard cap on total requests per scan;
 * - GET and HEAD only, through the SSRF-safe fetcher with the honest User-Agent;
 * - identical GETs within a scan are served from memory, so modules can share pages.
 */
export class PoliteClient {
  private constructor(
    private readonly shared: SharedState,
    private readonly moduleId: string | undefined,
  ) {}

  static create(options: {
    fetcher: Fetcher;
    limiter: RateLimiter;
    domain: string;
    maxRequests: number;
    signal?: AbortSignal;
  }): PoliteClient {
    const domain = options.domain.toLowerCase();
    const apex = domain.startsWith('www.') ? domain.slice(4) : domain;
    return new PoliteClient(
      {
        fetcher: options.fetcher,
        limiter: options.limiter,
        maxRequests: options.maxRequests,
        scope: new Set([apex, `www.${apex}`]),
        rateKey: apex,
        signal: options.signal,
        used: 0,
        perModule: new Map(),
        cache: new Map(),
      },
      undefined,
    );
  }

  /** A view of the same client that attributes requests to one module. */
  forModule(moduleId: string): PoliteClient {
    return new PoliteClient(this.shared, moduleId);
  }

  get requestCount(): number {
    return this.shared.used;
  }

  requestsBy(moduleId: string): number {
    return this.shared.perModule.get(moduleId) ?? 0;
  }

  get remaining(): number {
    return this.shared.maxRequests - this.shared.used;
  }

  inScope(url: string | URL): boolean {
    try {
      const u = typeof url === 'string' ? new URL(url) : url;
      return (u.protocol === 'https:' || u.protocol === 'http:') && this.shared.scope.has(u.hostname.toLowerCase());
    } catch {
      return false;
    }
  }

  get(url: string, options: Omit<PoliteRequestOptions, 'method'> = {}): Promise<PoliteResponse> {
    return this.request(url, { ...options, method: 'GET' });
  }

  head(url: string, options: Omit<PoliteRequestOptions, 'method'> = {}): Promise<PoliteResponse> {
    return this.request(url, { ...options, method: 'HEAD' });
  }

  private request(url: string, options: PoliteRequestOptions): Promise<PoliteResponse> {
    if (!this.inScope(url)) return Promise.reject(new OutOfScopeError(url));
    if (options.method === 'HEAD') return this.send(url, options);

    const key = `${url}|${options.followRedirects ? 1 : 0}|${options.maxBytes ?? ''}`;
    const cached = this.shared.cache.get(key);
    if (cached) return cached;
    const pending = this.send(url, options);
    this.shared.cache.set(key, pending);
    pending.catch(() => this.shared.cache.delete(key));
    return pending;
  }

  private async send(url: string, options: PoliteRequestOptions): Promise<PoliteResponse> {
    const s = this.shared;
    const redirects: string[] = [];
    let current = url;

    for (let hop = 0; ; hop++) {
      if (s.used >= s.maxRequests) throw new BudgetExhaustedError(s.maxRequests);
      s.used += 1;
      if (this.moduleId) s.perModule.set(this.moduleId, (s.perModule.get(this.moduleId) ?? 0) + 1);

      await s.limiter.acquire(s.rateKey, s.signal);
      const res = await s.fetcher.fetch(current, {
        method: options.method ?? 'GET',
        maxBytes: options.maxBytes ?? 256 * 1024,
        timeoutMs: options.timeoutMs ?? 15_000,
        redirect: 'none',
      });

      const location = typeof res.headers.location === 'string' ? res.headers.location : undefined;
      if (!options.followRedirects || !REDIRECTS.has(res.status) || !location || hop >= MAX_HOPS) {
        return { ...res, redirects, redirectedOffSite: false };
      }
      let next: URL;
      try {
        next = new URL(location, current);
      } catch {
        return { ...res, redirects, redirectedOffSite: false };
      }
      if (!this.inScope(next)) return { ...res, redirects, redirectedOffSite: true };
      current = next.toString();
      redirects.push(current);
    }
  }
}
