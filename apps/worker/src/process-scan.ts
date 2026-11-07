import { and, eq, lt, or, sql } from 'drizzle-orm';
import type { Config } from '@shc/config';
import { audit, ensureFreshVerification, markScanFailed } from '@shc/core';
import { scans, sites, type Database } from '@shc/db';
import type { Fetcher, OwnershipChecker } from '@shc/net';
import { runScan, ScanError, type CheckModule, type RateLimiter, type ScanLogger, type VulnLookup } from '@shc/scanner';
import { saveOutcome } from './persist';

export interface ProcessDeps {
  db: Database;
  ownership: OwnershipChecker;
  fetcher: Fetcher;
  limiter: RateLimiter;
  vulns: VulnLookup;
  scan: Config['scan'];
  log: ScanLogger & { error(obj: object, msg?: string): void };
  modules?: readonly CheckModule[];
}

export type ProcessResult = 'completed' | 'failed' | 'skipped';

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

  // Rule 1, enforced again right before we touch the site: the scan may have waited in
  // the queue, and ownership may have been withdrawn since it was requested.
  const fresh = await ensureFreshVerification(db, deps.ownership, scan.siteId);
  if (!fresh.ok) return fail(fresh.reason, 'not_verified');

  const [claimed] = await db
    .update(scans)
    .set({ status: 'running', startedAt: new Date() })
    .where(and(eq(scans.id, scanId), eq(scans.status, 'queued')))
    .returning({ id: scans.id });
  if (!claimed) return 'skipped';

  log.info({ scanId, domain }, 'scan started');
  try {
    const outcome = await runScan({
      domain,
      fetcher: deps.fetcher,
      limiter: deps.limiter,
      vulns: deps.vulns,
      maxRequests: deps.scan.maxRequests,
      timeoutMs: deps.scan.timeoutSeconds * 1000,
      modules: deps.modules,
      log,
    });
    await saveOutcome(db, scanId, scan.siteId, outcome);
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
