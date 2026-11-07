import { readFileSync } from 'node:fs';
import path from 'node:path';
import { NetError, type FetchOptions, type Fetcher, type NetErrorCode, type ProbeOptions, type SafeResponse, type TlsInspection, type TlsProbe } from '@shc/net';
import type { SoftwareType } from '@shc/shared';
import type { CoreStatus, ReleaseLookup, ScanLogger, VulnLookup, VulnRecord } from './types';

/**
 * Test doubles for the scanner. Check modules are tested against recorded HTTP
 * responses only, never live sites.
 */

export interface FixtureResponse {
  status?: number;
  /** Status for HEAD requests when it differs (e.g. 405 from servers that refuse HEAD). */
  headStatus?: number;
  headers?: Record<string, string | string[]>;
  body?: string;
  /** Simulate a network-level failure instead of a response. */
  error?: NetErrorCode;
}

/** Serves recorded responses by absolute URL; anything unknown is a 404. */
export class FixtureFetcher implements Fetcher {
  readonly requested: string[] = [];

  constructor(private readonly routes: Record<string, FixtureResponse>) {}

  async fetch(url: string, options: FetchOptions = {}): Promise<SafeResponse> {
    if (options.beforeSend) await options.beforeSend();
    this.requested.push(`${options.method ?? 'GET'} ${url}`);
    const route = this.routes[url];
    if (route?.error) throw new NetError(route.error, `simulated ${route.error}`, url);
    const body = Buffer.from(options.method === 'HEAD' ? '' : (route?.body ?? ''), 'utf8');
    const maxBytes = options.maxBytes ?? 256 * 1024;
    const status = route ? (options.method === 'HEAD' && route.headStatus ? route.headStatus : (route.status ?? 200)) : 404;
    return {
      url,
      status,
      headers: Object.fromEntries(Object.entries(route?.headers ?? {}).map(([k, v]) => [k.toLowerCase(), v])),
      body: body.subarray(0, maxBytes),
      truncated: body.length > maxBytes,
      remoteAddress: '203.0.113.10',
      redirects: [],
    };
  }
}

interface FixtureFile {
  description?: string;
  /** Origin the routes are relative to, e.g. https://example.com */
  origin: string;
  routes: Record<string, FixtureResponse & { bodyFile?: string }>;
}

/** Loads `<dir>/fixture.json`, resolving bodyFile entries relative to the directory. */
export function loadFixture(dir: string): { origin: string; routes: Record<string, FixtureResponse> } {
  const file = JSON.parse(readFileSync(path.join(dir, 'fixture.json'), 'utf8')) as FixtureFile;
  const routes: Record<string, FixtureResponse> = {};
  for (const [route, res] of Object.entries(file.routes)) {
    const { bodyFile, ...rest } = res;
    const url = /^https?:\/\//.test(route) ? route : `${file.origin}${route}`;
    routes[url] = bodyFile ? { ...rest, body: readFileSync(path.join(dir, bodyFile), 'utf8') } : rest;
  }
  return { origin: file.origin, routes };
}

export function memoryVulns(records: Partial<Record<`${SoftwareType}:${string}`, VulnRecord[]>>): VulnLookup {
  return { forComponent: async (type, slug) => records[`${type}:${slug}`] ?? [] };
}

export const noVulns: VulnLookup = { forComponent: async () => [] };

export const silentLog: ScanLogger = { debug() {}, info() {}, warn() {} };

/** Canned TLS answers per host; unknown hosts behave like "no HTTPS". */
export class FakeTlsProbe implements TlsProbe {
  readonly calls: string[] = [];
  constructor(
    private readonly hosts: Record<string, { inspection?: TlsInspection; legacy?: boolean }>,
  ) {}

  async inspect(host: string, options: ProbeOptions = {}): Promise<TlsInspection> {
    if (options.beforeConnect) await options.beforeConnect();
    this.calls.push(`inspect ${host}`);
    const h = this.hosts[host];
    if (!h?.inspection) throw new NetError('connect_failed', 'no TLS', `tls://${host}`);
    return h.inspection;
  }

  async acceptsLegacyTls(host: string, options: ProbeOptions = {}): Promise<boolean> {
    if (options.beforeConnect) await options.beforeConnect();
    this.calls.push(`legacy ${host}`);
    return this.hosts[host]?.legacy ?? false;
  }
}

/** A healthy certificate valid for `days` more days. */
export function goodTls(host: string, days = 60, over: Partial<TlsInspection> = {}): TlsInspection {
  return {
    protocol: 'TLSv1.3',
    trusted: true,
    trustError: null,
    hostnameMatches: true,
    certificate: {
      subjectCN: host,
      issuer: "Let's Encrypt",
      validFrom: new Date(Date.now() - 30 * 86_400_000).toISOString(),
      validTo: new Date(Date.now() + days * 86_400_000).toISOString(),
      daysRemaining: days,
      altNames: [host, `www.${host}`],
      selfSigned: false,
    },
    ...over,
  };
}

export function memoryReleases(data: {
  core?: { status: CoreStatus; latest: string };
  latest?: Record<string, string>;
}): ReleaseLookup {
  return {
    coreStatus: async () => data.core ?? null,
    latestVersion: async (type, slug) => data.latest?.[`${type}:${slug}`] ?? null,
  };
}
