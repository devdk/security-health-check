import type { AffectedRange } from '@shc/db';
import type { Severity } from '@shc/shared';
import { fetchJson as defaultFetchJson, IntelError, type FetchJson } from './http';
import { clip, httpUrl, type IntelLogger, type NormalizedVuln, type VulnSourceAdapter } from './types';

export const NVD_CVE_API = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
/** CPE for the PHP interpreter. */
export const PHP_CPE = 'cpe:2.3:a:php:php';
const PAGE_SIZE = 2000;
/** NVD only accepts lastModified windows up to 120 days. */
const MAX_WINDOW_DAYS = 120;

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => typeof v === 'object' && v !== null && !Array.isArray(v);
const arr = (v: unknown): unknown[] => (Array.isArray(v) ? v : []);
const str = (v: unknown) => (typeof v === 'string' ? v : undefined);

const SEVERITY: Record<string, Severity> = { CRITICAL: 'critical', HIGH: 'high', MEDIUM: 'medium', LOW: 'low', NONE: 'info' };

function cvssOf(metrics: unknown): { score: number | null; severity: Severity | null } {
  if (!isObj(metrics)) return { score: null, severity: null };
  for (const key of ['cvssMetricV40', 'cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']) {
    const m = arr(metrics[key])[0];
    if (!isObj(m) || !isObj(m.cvssData)) continue;
    const score = typeof m.cvssData.baseScore === 'number' ? m.cvssData.baseScore : null;
    const sev = str(m.cvssData.baseSeverity) ?? str(m.baseSeverity);
    return { score, severity: sev ? (SEVERITY[sev.toUpperCase()] ?? null) : null };
  }
  return { score: null, severity: null };
}

/** Affected PHP ranges from configurations -> nodes -> cpeMatch. */
function phpRanges(configurations: unknown): AffectedRange[] {
  const out: AffectedRange[] = [];
  for (const config of arr(configurations)) {
    for (const node of arr(isObj(config) ? config.nodes : undefined)) {
      if (!isObj(node) || node.negate === true) continue;
      for (const match of arr(node.cpeMatch)) {
        if (!isObj(match) || match.vulnerable !== true) continue;
        const criteria = str(match.criteria) ?? '';
        if (!criteria.startsWith(`${PHP_CPE}:`)) continue;
        const exact = criteria.split(':')[5];
        const start = str(match.versionStartIncluding) ?? str(match.versionStartExcluding);
        const end = str(match.versionEndIncluding) ?? str(match.versionEndExcluding);
        if (start || end) {
          out.push({
            from: start ?? '*',
            fromInclusive: match.versionStartExcluding === undefined,
            to: end ?? '*',
            toInclusive: match.versionEndExcluding === undefined,
          });
        } else if (exact && exact !== '*' && exact !== '-') {
          out.push({ from: exact, fromInclusive: true, to: exact, toInclusive: true });
        }
      }
    }
  }
  return out;
}

/** One NVD CVE item → a PHP-runtime cache row, or null when it has no PHP range. */
export function parseNvdCve(item: unknown): NormalizedVuln | null {
  const cve = isObj(item) && isObj(item.cve) ? item.cve : null;
  if (!cve) return null;
  const id = str(cve.id);
  if (!id || !/^CVE-\d{4}-\d{4,}$/.test(id) || /reject/i.test(str(cve.vulnStatus) ?? '')) return null;
  const affected = phpRanges(cve.configurations);
  if (affected.length === 0) return null;

  const description = arr(cve.descriptions).find((d) => isObj(d) && d.lang === 'en') as Obj | undefined;
  const text = clip(description?.value, 5000);
  const firstSentence = text?.split(/(?<=\.)\s/)[0] ?? 'PHP vulnerability';
  const { score, severity } = cvssOf(cve.metrics);
  const cweText = arr(cve.weaknesses)
    .flatMap((w) => arr(isObj(w) ? w.description : undefined))
    .map((d) => str(isObj(d) ? d.value : undefined))
    .find((v) => v && /^CWE-\d+$/.test(v));

  return {
    source: 'nvd',
    sourceId: id,
    softwareType: 'php',
    slug: 'php',
    title: clip(firstSentence, 200) ?? id,
    cveIds: [id],
    cvssScore: score,
    severity,
    affected,
    fixedIn: null,
    references: arr(cve.references)
      .map((r) => httpUrl(isObj(r) ? r.url : undefined))
      .filter((u): u is string => u !== null)
      .slice(0, 5)
      .map((url) => ({ type: 'advisory' as const, url })),
    informational: false,
    description: text,
    remediation: null,
    cwe: cweText ? { id: Number(cweText.slice(4)), name: cweText } : null,
    recordUrl: `https://nvd.nist.gov/vuln/detail/${id}`,
    copyrights: null,
    publishedAt: str(cve.published) ? new Date(`${str(cve.published)}Z`.replace(/ZZ$/, 'Z')) : null,
    updatedAt: str(cve.lastModified) ? new Date(`${str(cve.lastModified)}Z`.replace(/ZZ$/, 'Z')) : null,
  };
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/**
 * NVD CVE API 2.0, used for PHP-runtime vulnerabilities. Incremental: after the first
 * full download only records modified since the last successful run are fetched.
 * Shown with the notice "uses data from the NVD API but is not endorsed or certified by the NVD".
 */
export class NvdAdapter implements VulnSourceAdapter {
  readonly source = 'nvd' as const;
  readonly mode = 'incremental' as const;

  constructor(private readonly options: { apiKey?: string; fetchJson?: FetchJson; pauseMs?: number } = {}) {}

  disabledReason(): string | null {
    return null;
  }

  async fetch({ since, log }: { since?: Date; log?: IntelLogger } = {}): Promise<NormalizedVuln[]> {
    const get = this.options.fetchJson ?? defaultFetchJson;
    // Public limit: 5 requests per 30 s without a key, 50 with one.
    const pause = this.options.pauseMs ?? (this.options.apiKey ? 700 : 6500);
    const now = new Date();
    const windowStart = since && now.getTime() - since.getTime() < MAX_WINDOW_DAYS * 86_400_000 ? since : undefined;

    const rows: NormalizedVuln[] = [];
    let startIndex = 0;
    for (let page = 0; page < 50; page++) {
      const params = new URLSearchParams({ virtualMatchString: PHP_CPE, resultsPerPage: String(PAGE_SIZE), startIndex: String(startIndex) });
      if (windowStart) {
        params.set('lastModStartDate', windowStart.toISOString());
        params.set('lastModEndDate', now.toISOString());
      }
      const res = await get(`${NVD_CVE_API}?${params}`, {
        headers: this.options.apiKey ? { apiKey: this.options.apiKey } : {},
        timeoutMs: 120_000,
        maxBytes: 100 * 1024 * 1024,
      });
      if (res.status === 403 || res.status === 429) throw new IntelError('NVD rate limit reached; will retry on the next run', res.status);
      if (res.status !== 200 || !isObj(res.json)) throw new IntelError(`Unexpected NVD response (HTTP ${res.status})`, res.status);

      const items = arr(res.json.vulnerabilities);
      for (const item of items) {
        const row = parseNvdCve(item);
        if (row) rows.push(row);
      }
      const total = typeof res.json.totalResults === 'number' ? res.json.totalResults : 0;
      startIndex += items.length;
      if (items.length === 0 || startIndex >= total) break;
      await sleep(pause);
    }
    log?.info({ rows: rows.length, incremental: Boolean(windowStart) }, 'nvd php cves fetched');
    return rows;
  }
}
