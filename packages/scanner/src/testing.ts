import { readFileSync } from 'node:fs';
import path from 'node:path';
import { NetError, type FetchOptions, type Fetcher, type NetErrorCode, type SafeResponse } from '@shc/net';
import type { SoftwareType } from '@shc/shared';
import type { ScanLogger, VulnLookup, VulnRecord } from './types';

/**
 * Test doubles for the scanner. Check modules are tested against recorded HTTP
 * responses only, never live sites.
 */

export interface FixtureResponse {
  status?: number;
  headers?: Record<string, string>;
  body?: string;
  /** Simulate a network-level failure instead of a response. */
  error?: NetErrorCode;
}

/** Serves recorded responses by absolute URL; anything unknown is a 404. */
export class FixtureFetcher implements Fetcher {
  readonly requested: string[] = [];

  constructor(private readonly routes: Record<string, FixtureResponse>) {}

  async fetch(url: string, options: FetchOptions = {}): Promise<SafeResponse> {
    this.requested.push(`${options.method ?? 'GET'} ${url}`);
    const route = this.routes[url];
    if (route?.error) throw new NetError(route.error, `simulated ${route.error}`, url);
    const body = Buffer.from(options.method === 'HEAD' ? '' : (route?.body ?? ''), 'utf8');
    const maxBytes = options.maxBytes ?? 256 * 1024;
    return {
      url,
      status: route ? (route.status ?? 200) : 404,
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
