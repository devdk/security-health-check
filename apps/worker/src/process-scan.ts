import { and, eq, lt, or, sql } from 'drizzle-orm';
import { parseInsideReport } from '@shc/companion';
import type { Config } from '@shc/config';
import { audit, ensureFreshVerification, markScanFailed } from '@shc/core';
import { pluginReports, scans, sites, type Database } from '@shc/db';
import type { Fetcher, OwnershipChecker, TlsProbe } from '@shc/net';
import {
  analyseInside,
  runScan,
  ScanError,
  type CheckModule,
  type RateLimiter,
  type ReleaseLookup,
  type ScanLogger,
  type ScanOutcome,
  type VulnLookup,
} from '@shc/scanner';
import { saveOutcome } from './persist';

export interface ProcessDeps {
  db: Database;
  ownership: OwnershipChecker;
  fetcher: Fetcher;
  limiter: RateLimiter;
  vulns: VulnLookup;
  releases?: ReleaseLookup;
  tlsProbe?: TlsProbe;
  scan: Config['scan'];
  log: ScanLogger & { error(obj: object, msg?: string): void };
  modules?: readonly CheckModule[];
}

export type ProcessResult = 'completed' | 'failed' | 'skipped';

type ScanRow = typeof scans.$inferSelect;
type Prepared = { ok: true; run: () => Promise<ScanOutcome> } | { ok: false; reason: string; code: string };

/** What each kind of scan checks before it may start, and how it then produces its outcome. */
async function prepare(scan: ScanRow, domain: string, deps: ProcessDeps): Promise<Prepared> {
  if (scan.kind === 'inside') {
    // Built from the report the plugin sent: no ownership re-check, because nothing goes to the site.
    const [stored] = await deps.db.select({ payload: pluginReports.payload }).from(pluginReports).where(eq(pluginReports.scanId, scan.id)).limit(1);
    const parsed = stored ? parseInsideReport(stored.payload) : null;
    if (!parsed?.ok) return { ok: false, reason: 'The report sent by the companion plugin could not be read.', code: 'invalid_report' };
    return { ok: true, run: () => analyseInside(parsed.report, { vulns: deps.vulns, releases: deps.releases, log: deps.log }) };
  }

  // Rule 1, enforced again right before we touch the site: the scan may have waited in
  // the queue, and ownership may have been withdrawn since it was requested.
  const fresh = await ensureFreshVerification(deps.db, deps.ownership, scan.siteId);
  if (!fresh.ok) return { ok: false, reason: fresh.reason, code: 'not_verified' };
  return {
    ok: true,
    run: () =>
      runScan({
        domain,
        fetcher: deps.fetcher,
        limiter: deps.limiter,
        vulns: deps.vulns,
        releases: deps.releases,
        tlsProbe: deps.tlsProbe,
        maxRequests: deps.scan.maxRequests,
        timeoutMs: deps.scan.timeoutSeconds * 1000,
        modules: deps.modules,
        log: deps.log,
      }),
  };
}

/**
 * Runs one queued scan. Safe to call twice for the same id: only the call that moves the
 * scan from queued to running does any work.
 */
export async function processScan(scanId: string, deps: ProcessDeps): Promise<ProcessResult> {
  const { db, log } = deps;
  const [row] = await db
    .select({ scan: scans, domain: sites.domain })
    .from(scans)
    .innerJoin(sites, eq(sites.id, scans.siteId))
    .where(eq(scans.id, scanId))
    .limit(1);
  if (!row || row.scan.status !== 'queued') return 'skipped';
  const { scan, domain } = row;

  const fail = async (reason: string, code: string) => {
    await markScanFailed(db, scanId, reason);
    await audit(db, { event: 'scan_failed', userId: scan.requestedBy, siteId: scan.siteId, meta: { scanId, code } });
    return 'failed' as const;
  };

  const prepared = await prepare(scan, domain, deps);
  if (!prepared.ok) return fail(prepared.reason, prepared.code);

  const [claimed] = await db
    .update(scans)
    .set({ status: 'running', startedAt: new Date() })
    .where(and(eq(scans.id, scanId), eq(scans.status, 'queued')))
    .returning({ id: scans.id });
  if (!claimed) return 'skipped';

  log.info({ scanId, domain, kind: scan.kind }, 'scan started');
  try {
    const outcome = await prepared.run();
    await saveOutcome(db, scan, outcome);
    await audit(db, {
      event: 'scan_completed',
      userId: scan.requestedBy,
      siteId: scan.siteId,
      meta: { scanId, requests: outcome.requestCount, findings: outcome.findings.length },
    });
    log.info({ scanId, requests: outcome.requestCount, findings: outcome.findings.length }, 'scan completed');
    return 'completed';
  } catch (err) {
    if (err instanceof ScanError) return fail(err.message, err.code);
    log.error({ scanId, err }, 'scan crashed');
    return fail('The scan stopped because of an internal error. Please try again later.', 'internal');
  }
}

/** Fails scans abandoned by a crashed worker so they stop blocking new scans of the site. */
export async function failStuckScans(db: Database, opts: { runningMinutes: number; queuedMinutes: number }): Promise<number> {
  const stuck = await db
    .update(scans)
    .set({ status: 'failed', finishedAt: new Date(), error: 'The scan did not finish in time and was stopped.' })
    .where(
      or(
        and(eq(scans.status, 'running'), lt(scans.startedAt, sql`now() - make_interval(mins => ${opts.runningMinutes})`)),
        and(eq(scans.status, 'queued'), lt(scans.createdAt, sql`now() - make_interval(mins => ${opts.queuedMinutes})`)),
      ),
    )
    .returning({ id: scans.id });
  return stuck.length;
}
