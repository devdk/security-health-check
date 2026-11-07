import { and, desc, eq, lt, sql } from 'drizzle-orm';
import { softwareReleases, vulnCache, vulnSyncRuns, type Database } from '@shc/db';
import type { FetchJson } from './http';
import { quietLogger, type IntelLogger, type NormalizedVuln, type VulnSourceAdapter } from './types';
import { fetchCoreStatus } from './wporg';

export type SyncResult = { source: string; status: 'ok' | 'skipped' | 'failed'; rows: number; removed?: number; note?: string };

const CHUNK = 500;
const UPDATABLE = [
  'title',
  'cve_ids',
  'cvss_score',
  'severity',
  'affected',
  'fixed_in',
  'references',
  'informational',
  'description',
  'remediation',
  'cwe',
  'record_url',
  'copyrights',
  'published_at',
  'updated_at',
] as const;

function toRow(v: NormalizedVuln) {
  return {
    source: v.source,
    sourceId: v.sourceId,
    softwareType: v.softwareType,
    slug: v.slug,
    title: v.title,
    cveIds: v.cveIds,
    cvssScore: v.cvssScore === null ? null : v.cvssScore.toFixed(1),
    severity: v.severity,
    affected: v.affected,
    fixedIn: v.fixedIn,
    references: v.references,
    informational: v.informational,
    description: v.description,
    remediation: v.remediation,
    cwe: v.cwe,
    recordUrl: v.recordUrl,
    copyrights: v.copyrights,
    publishedAt: v.publishedAt,
    updatedAt: v.updatedAt,
    syncedAt: new Date(),
  };
}

/**
 * Pulls one source into vuln_cache and records the run in vuln_sync_runs.
 * Full sources (Wordfence) also drop rows that vanished from the feed, unless the feed
 * came back suspiciously small, which looks like an upstream problem rather than reality.
 */
export async function syncVulnSource(db: Database, adapter: VulnSourceAdapter, log: IntelLogger = quietLogger): Promise<SyncResult> {
  const disabled = adapter.disabledReason();
  if (disabled) {
    log.info({ source: adapter.source, reason: disabled }, 'vulnerability source skipped');
    return { source: adapter.source, status: 'skipped', rows: 0, note: disabled };
  }

  const [lastOk] = await db
    .select({ startedAt: vulnSyncRuns.startedAt })
    .from(vulnSyncRuns)
    .where(and(eq(vulnSyncRuns.source, adapter.source), eq(vulnSyncRuns.status, 'ok')))
    .orderBy(desc(vulnSyncRuns.startedAt))
    .limit(1);
  const [run] = await db.insert(vulnSyncRuns).values({ source: adapter.source, status: 'running' }).returning();

  try {
    const fetched = await adapter.fetch({ since: adapter.mode === 'incremental' && lastOk ? new Date(lastOk.startedAt.getTime() - 86_400_000) : undefined, log });
    // One row per (source, id, type, slug); a statement may not update the same row twice.
    const unique = [...new Map(fetched.map((v) => [`${v.sourceId}|${v.softwareType}|${v.slug}`, v])).values()];

    for (let i = 0; i < unique.length; i += CHUNK) {
      await db
        .insert(vulnCache)
        .values(unique.slice(i, i + CHUNK).map(toRow))
        .onConflictDoUpdate({
          target: [vulnCache.source, vulnCache.sourceId, vulnCache.softwareType, vulnCache.slug],
          set: { ...Object.fromEntries(UPDATABLE.map((c) => [c, sql.raw(`excluded.${c}`)])), syncedAt: sql`now()` },
        });
    }

    let removed = 0;
    let note: string | undefined;
    if (adapter.mode === 'full') {
      const [{ n: existing } = { n: 0 }] = await db
        .select({ n: sql<number>`count(*)::int` })
        .from(vulnCache)
        .where(eq(vulnCache.source, adapter.source));
      if (unique.length > 0 && unique.length >= existing * 0.5) {
        const gone = await db
          .delete(vulnCache)
          .where(and(eq(vulnCache.source, adapter.source), lt(vulnCache.syncedAt, run!.startedAt)))
          .returning({ id: vulnCache.id });
        removed = gone.length;
      } else {
        note = `feed returned ${unique.length} rows against ${existing} cached; kept old rows`;
        log.warn({ source: adapter.source, fetched: unique.length, existing }, 'suspiciously small feed; skipped removals');
      }
    }

    await db
      .update(vulnSyncRuns)
      .set({ status: 'ok', finishedAt: new Date(), recordsUpserted: unique.length, error: note ?? null })
      .where(eq(vulnSyncRuns.id, run!.id));
    log.info({ source: adapter.source, rows: unique.length, removed }, 'vulnerability source synced');
    return { source: adapter.source, status: 'ok', rows: unique.length, removed, note };
  } catch (err) {
    const message = (err instanceof Error ? err.message : String(err)).slice(0, 500);
    await db.update(vulnSyncRuns).set({ status: 'failed', finishedAt: new Date(), error: message }).where(eq(vulnSyncRuns.id, run!.id));
    log.warn({ source: adapter.source, error: message }, 'vulnerability source failed');
    return { source: adapter.source, status: 'failed', rows: 0, note: message };
  }
}

/** Refreshes WordPress core release status from WordPress.org. */
export async function refreshCoreReleases(db: Database, get?: FetchJson): Promise<{ latest: string; versions: number }> {
  const { latest, versions } = await fetchCoreStatus(get);
  await db
    .insert(softwareReleases)
    .values({ softwareType: 'core', slug: 'wordpress', latestVersion: latest, found: true, details: { versions }, fetchedAt: new Date() })
    .onConflictDoUpdate({
      target: [softwareReleases.softwareType, softwareReleases.slug],
      set: { latestVersion: latest, found: true, details: { versions }, fetchedAt: sql`now()` },
    });
  return { latest, versions: Object.keys(versions).length };
}

/** The daily job: core release data, then every vulnerability source. One failure never stops the others. */
export async function runIntelRefresh(
  db: Database,
  adapters: readonly VulnSourceAdapter[],
  options: { log?: IntelLogger; fetchJson?: FetchJson } = {},
): Promise<{ core: string; sources: SyncResult[] }> {
  const log = options.log ?? quietLogger;
  let core: string;
  try {
    const r = await refreshCoreReleases(db, options.fetchJson);
    core = `ok (latest ${r.latest})`;
    log.info({ latest: r.latest, versions: r.versions }, 'wordpress core releases refreshed');
  } catch (err) {
    core = `failed: ${err instanceof Error ? err.message : String(err)}`;
    log.warn({ error: core }, 'wordpress core releases refresh failed');
  }
  const sources: SyncResult[] = [];
  for (const adapter of adapters) sources.push(await syncVulnSource(db, adapter, log));
  return { core, sources };
}
