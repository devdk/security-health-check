import { NetError, type Fetcher, type TlsProbe } from '@shc/net';
import { ONTOLOGY_VERSION, isExposureId } from '@shc/ontology';
import { SEVERITIES } from '@shc/shared';
import { ComponentStore } from './components';
import { snippet } from './html';
import { ALL_MODULES } from './modules';
import { BudgetExhaustedError, PoliteClient } from './polite-client';
import type { RateLimiter } from './rate-limit';
import type { CheckModule, ComponentFact, Finding, ReleaseLookup, ScanContext, ScanLogger, ScanTarget, VulnLookup } from './types';

export interface ModuleOutcome {
  module: string;
  status: 'ok' | 'skipped' | 'failed' | 'budget_exhausted';
  durationMs: number;
  requests: number;
  findings: number;
  note?: string;
}

export interface ScanOutcome {
  baseUrl: string;
  ontologyVersion: string;
  components: ComponentFact[];
  findings: Finding[];
  modules: ModuleOutcome[];
  requestCount: number;
}

export class ScanError extends Error {
  constructor(
    public readonly code: 'unreachable' | 'timeout',
    message: string,
  ) {
    super(message);
    this.name = 'ScanError';
  }
}

export interface RunScanOptions {
  domain: string;
  fetcher: Fetcher;
  limiter: RateLimiter;
  vulns: VulnLookup;
  /** Latest-release data; without it the outdated-software check finds nothing. */
  releases?: ReleaseLookup;
  /** HTTPS inspection; without it the tls check is recorded as failed. */
  tlsProbe?: TlsProbe;
  maxRequests: number;
  timeoutMs: number;
  modules?: readonly CheckModule[];
  log?: ScanLogger;
}

const quietLog: ScanLogger = { debug() {}, info() {}, warn() {} };
export const noReleases: ReleaseLookup = { coreStatus: async () => null, latestVersion: async () => null };

/** Finds where the site actually lives: https first, then http, following on-site redirects. */
async function resolveBaseUrl(http: PoliteClient, domain: string): Promise<string> {
  let lastError: unknown;
  for (const scheme of ['https', 'http']) {
    try {
      const res = await http.get(`${scheme}://${domain}/`, { followRedirects: true, maxBytes: 512 * 1024 });
      const finalUrl = new URL(res.redirects.at(-1) ?? res.url);
      return finalUrl.origin;
    } catch (err) {
      lastError = err;
      if (err instanceof NetError && (err.code === 'connect_failed' || err.code === 'tls_failed' || err.code === 'timeout')) continue;
      break;
    }
  }
  const reason = lastError instanceof NetError ? lastError.message : 'no response';
  throw new ScanError('unreachable', `We couldn't reach ${domain} over HTTPS or HTTP (${reason}).`);
}

/** Drops findings that point outside the ontology or claim another module's id, and trims what came from the site. */
export function sanitiseFinding(f: Finding, moduleId: string): Finding | null {
  if (!isExposureId(f.conceptId) || !(SEVERITIES as readonly string[]).includes(f.severity)) return null;
  if (!f.checkId.startsWith(`${moduleId}.`)) return null;
  return {
    ...f,
    title: f.title.slice(0, 300),
    evidence: { ...f.evidence, ...(f.evidence.snippet ? { snippet: snippet(f.evidence.snippet, 300) } : {}) },
  };
}

/**
 * Runs every module against one verified domain. Stage 1 modules run in parallel and
 * gather facts; stage 2 modules then analyse them. All requests share one PoliteClient,
 * so the rate limit and request cap hold across modules. A failing module never sinks
 * the scan; its outcome is recorded instead.
 */
export async function runScan(options: RunScanOptions): Promise<ScanOutcome> {
  const log = options.log ?? quietLog;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(new ScanError('timeout', 'Scan time limit reached')), options.timeoutMs);

  try {
    const http = PoliteClient.create({
      fetcher: options.fetcher,
      limiter: options.limiter,
      domain: options.domain,
      maxRequests: options.maxRequests,
      signal: controller.signal,
      tlsProbe: options.tlsProbe,
    });
    const baseUrl = await resolveBaseUrl(http, options.domain);
    const target: ScanTarget = { domain: options.domain, baseUrl };
    const components = new ComponentStore();
    const modules = options.modules ?? ALL_MODULES;
    const findings: Finding[] = [];
    const outcomes: ModuleOutcome[] = [];

    const runOne = async (m: CheckModule): Promise<void> => {
      const started = Date.now();
      const ctx: ScanContext = { http: http.forModule(m.id), components, vulns: options.vulns, releases: options.releases ?? noReleases, log };
      let status: ModuleOutcome['status'] = 'ok';
      let note: string | undefined;
      let produced: Finding[] = [];
      try {
        if (controller.signal.aborted) throw controller.signal.reason;
        produced = await m.run(target, ctx);
      } catch (err) {
        if (err instanceof BudgetExhaustedError) {
          status = 'budget_exhausted';
          note = err.message;
        } else {
          status = 'failed';
          note = err instanceof ScanError ? err.message : 'Check failed unexpectedly';
          log.warn({ module: m.id, err: String(err) }, 'check module failed');
        }
      }
      const valid = produced.map((f) => sanitiseFinding(f, m.id)).filter((f): f is Finding => f !== null);
      if (valid.length !== produced.length) log.warn({ module: m.id, dropped: produced.length - valid.length }, 'dropped malformed findings');
      findings.push(...valid);
      outcomes.push({ module: m.id, status, durationMs: Date.now() - started, requests: http.requestsBy(m.id), findings: valid.length, note });
    };

    for (const stage of [1, 2] as const) {
      await Promise.all(modules.filter((m) => m.stage === stage).map(runOne));
    }

    return {
      baseUrl,
      ontologyVersion: ONTOLOGY_VERSION,
      components: components.list(),
      findings,
      modules: outcomes.sort((a, b) => a.module.localeCompare(b.module)),
      requestCount: http.requestCount,
    };
  } finally {
    clearTimeout(timer);
  }
}
