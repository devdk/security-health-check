import type { AffectedRange, VulnCopyrights } from '@shc/db';
import { compareVersions } from '@shc/scanner';
import type { Severity, SoftwareType } from '@shc/shared';
import { fetchJson as defaultFetchJson, IntelError, type FetchJson } from './http';
import { clip, httpUrl, type IntelLogger, type NormalizedVuln, type VulnSourceAdapter } from './types';

export const WORDFENCE_PRODUCTION_FEED = 'https://www.wordfence.com/api/intelligence/v3/vulnerabilities/production';

const TYPES: Record<string, SoftwareType> = { core: 'core', plugin: 'plugin', theme: 'theme' };
const RATINGS: Record<string, Severity> = { critical: 'critical', high: 'high', medium: 'medium', low: 'low', none: 'info' };
const SLUG = /^[a-z0-9][a-z0-9._-]{0,199}$/;

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => typeof v === 'object' && v !== null && !Array.isArray(v);
const str = (v: unknown) => (typeof v === 'string' ? v : undefined);

/** "YYYY-MM-DD hh:mm:ss" in UTC, per the feed documentation. */
function parseDate(v: unknown): Date | null {
  const s = str(v);
  if (!s || !/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(s)) return null;
  const d = new Date(`${s.replace(' ', 'T')}Z`);
  return Number.isNaN(d.getTime()) ? null : d;
}

function parseCopyrights(v: unknown): VulnCopyrights | null {
  if (!isObj(v)) return null;
  const holders: VulnCopyrights['holders'] = {};
  for (const [key, value] of Object.entries(v)) {
    if (!isObj(value)) continue;
    const notice = clip(value.notice, 500);
    const license = clip(value.license, 4000);
    if (!notice || !license) continue;
    holders[key] = { notice, license, licenseUrl: httpUrl(value.license_url) ?? '' };
  }
  if (Object.keys(holders).length === 0) return null;
  return { message: clip(v.message, 300) ?? undefined, holders };
}

function parseRanges(v: unknown): AffectedRange[] {
  if (!isObj(v)) return [];
  const out: AffectedRange[] = [];
  for (const range of Object.values(v)) {
    if (!isObj(range)) continue;
    const from = str(range.from_version);
    const to = str(range.to_version);
    if (!from && !to) continue;
    out.push({
      from: from ?? '*',
      fromInclusive: range.from_inclusive !== false,
      to: to ?? '*',
      toInclusive: range.to_inclusive !== false,
    });
  }
  return out;
}

/**
 * Turns one Wordfence v3 production record into cache rows, one per affected piece of
 * software. Malformed parts are skipped rather than failing the whole feed.
 */
export function parseWordfenceRecord(record: unknown): NormalizedVuln[] {
  if (!isObj(record)) return [];
  const id = str(record.id);
  const title = clip(record.title, 500);
  if (!id || !/^[0-9a-f-]{36}$/i.test(id) || !title || !Array.isArray(record.software)) return [];

  const references = (Array.isArray(record.references) ? record.references : []).map(httpUrl).filter((u): u is string => u !== null);
  const recordUrl = references.find((u) => /wordfence\.com\/threat-intel\/vulnerabilities\//i.test(u)) ?? null;
  const cve = str(record.cve);
  const cvss = isObj(record.cvss) ? record.cvss : null;
  const score = typeof cvss?.score === 'number' && cvss.score >= 0 && cvss.score <= 10 ? cvss.score : null;
  const rating = str(cvss?.rating)?.toLowerCase();
  const informational = record.informational === true;
  const cwe = isObj(record.cwe) && typeof record.cwe.id === 'number' ? { id: record.cwe.id, name: clip(record.cwe.name, 300) ?? '' } : null;

  const rows: NormalizedVuln[] = [];
  for (const sw of record.software) {
    if (!isObj(sw)) continue;
    const softwareType = TYPES[str(sw.type) ?? ''];
    const slug = str(sw.slug)?.toLowerCase();
    const affected = parseRanges(sw.affected_versions);
    if (!softwareType || !slug || !SLUG.test(slug) || affected.length === 0) continue;
    const patched = (Array.isArray(sw.patched_versions) ? sw.patched_versions : []).filter((p): p is string => typeof p === 'string');
    const fixedIn = patched.sort(compareVersions)[0] ?? null;
    rows.push({
      source: 'wordfence',
      sourceId: id,
      softwareType,
      slug,
      title,
      cveIds: cve && /^CVE-\d{4}-\d{4,}$/.test(cve) ? [cve] : [],
      cvssScore: score,
      severity: informational ? 'info' : (RATINGS[rating ?? ''] ?? null),
      affected,
      fixedIn,
      references: references.slice(0, 10).map((url) => ({ type: 'advisory' as const, url })),
      informational,
      description: clip(record.description, 5000),
      remediation: clip(sw.remediation, 1000),
      cwe,
      recordUrl,
      copyrights: parseCopyrights(record.copyrights),
      publishedAt: parseDate(record.published),
      updatedAt: parseDate(record.updated),
    });
  }
  return rows;
}

/**
 * Wordfence Intelligence v3 production feed. Free for commercial use; needs a free
 * wordfence.com account API key. The whole feed comes back on every call, so this is a
 * full sync. Attribution data travels with each row (copyrights, recordUrl).
 */
export class WordfenceAdapter implements VulnSourceAdapter {
  readonly source = 'wordfence' as const;
  readonly mode = 'full' as const;

  constructor(private readonly options: { apiKey?: string; fetchJson?: FetchJson; url?: string }) {}

  disabledReason(): string | null {
    return this.options.apiKey ? null : 'WORDFENCE_API_KEY is not set (create a free key at wordfence.com → Account → Integrations)';
  }

  async fetch({ log }: { log?: IntelLogger } = {}): Promise<NormalizedVuln[]> {
    if (!this.options.apiKey) throw new IntelError(this.disabledReason()!);
    const res = await (this.options.fetchJson ?? defaultFetchJson)(this.options.url ?? WORDFENCE_PRODUCTION_FEED, {
      headers: { authorization: `Bearer ${this.options.apiKey}` },
      timeoutMs: 300_000,
      maxBytes: 600 * 1024 * 1024,
    });
    if (res.status === 401 || res.status === 403) throw new IntelError('Wordfence rejected the API key', res.status);
    if (res.status === 429) throw new IntelError('Wordfence rate limit reached; will retry on the next run', res.status);
    if (res.status !== 200 || !isObj(res.json)) throw new IntelError(`Unexpected Wordfence response (HTTP ${res.status})`, res.status);

    const rows = Object.values(res.json).flatMap(parseWordfenceRecord);
    log?.info({ records: Object.keys(res.json).length, rows: rows.length }, 'wordfence feed parsed');
    return rows;
  }
}
