export class ApiError extends Error {
  constructor(
    public readonly status: number,
    public readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

export interface User {
  id: string;
  email: string;
  emailVerified: boolean;
  plan: 'free' | 'pro';
}

export type SiteStatus = 'verified' | 'stale' | 'unverified';
export type VerifyMethod = 'dns_txt' | 'file';

export interface Site {
  id: string;
  domain: string;
  status: SiteStatus;
  verificationMethod: VerifyMethod | null;
  verifiedAt: string | null;
  lastVerifyAttemptAt: string | null;
  lastVerifyError: string | null;
  createdAt: string;
  weeklyScan: boolean;
  nextScanAt: string | null;
  instructions: {
    dns: { name: string; type: 'TXT'; value: string };
    file: { filename: string; url: string; content: string };
  };
}

// Report types come from the server package, type-only, so the shapes can't drift.
export type { LockedFinding, ReportFinding, ReportView, RevealedFinding } from '@shc/report';

export interface Billing {
  plan: 'free' | 'pro';
  status: string;
  provider: string;
  currentPeriodEnd: string | null;
  upgradesAvailable: boolean;
  testMode: boolean;
}

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type ScanStatus = 'queued' | 'running' | 'completed' | 'failed';

export interface ScanSummary {
  id: string;
  siteId: string;
  status: ScanStatus;
  trigger: 'manual' | 'scheduled' | 'plugin';
  createdAt: string;
  startedAt: string | null;
  finishedAt: string | null;
  requestCount: number;
  baseUrl: string | null;
  error: string | null;
  score: number | null;
  grade: string | null;
  findingCounts: Record<Severity, number>;
}

export interface ScanDetail extends ScanSummary {
  domain: string;
  components: Array<{
    type: 'core' | 'plugin' | 'theme' | 'php' | 'web_server';
    slug: string;
    name: string | null;
    version: string | null;
    versionConfidence: 'confirmed' | 'likely' | 'possible' | null;
  }>;
  modules: Array<{ module: string; status: 'ok' | 'skipped' | 'failed' | 'budget_exhausted'; durationMs: number; requests: number; findings: number; note?: string }>;
}

/** JSON fetch against our own API. Cookies are first-party, so nothing is stored in JS. */
export async function api<T>(path: string, options: { method?: string; body?: unknown } = {}): Promise<T> {
  const init: RequestInit = {
    method: options.method ?? (options.body === undefined ? 'GET' : 'POST'),
    credentials: 'same-origin',
    headers: options.body === undefined ? {} : { 'Content-Type': 'application/json' },
  };
  if (options.body !== undefined) init.body = JSON.stringify(options.body);

  const res = await fetch(`/api${path}`, init);
  if (res.status === 204) return undefined as T;
  const data = (await res.json().catch(() => ({}))) as Record<string, unknown>;
  if (!res.ok) {
    throw new ApiError(
      res.status,
      typeof data.error === 'string' ? data.error : 'error',
      typeof data.message === 'string' ? data.message : 'Something went wrong. Please try again.',
    );
  }
  return data as T;
}

export function errorMessage(err: unknown): string {
  if (err instanceof ApiError) return err.message;
  return 'Could not reach the server. Check your connection and try again.';
}
