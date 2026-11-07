import { and, desc, eq, inArray, sql } from 'drizzle-orm';
import { createScanRequest, markScanFailed, type ScanQueue } from '@shc/core';
import { findings, scans, siteComponents, sites, type Database, type ModuleResult } from '@shc/db';
import type { OwnershipChecker } from '@shc/net';
import { SEVERITIES, type Confidence, type ScanStatus, type ScanTrigger, type Severity, type SoftwareType } from '@shc/shared';
import { HttpError } from '../lib/errors';
import type { RequestContext } from './auth-service';

export type SeverityCounts = Record<Severity, number>;

export interface ScanSummaryDto {
  id: string;
  siteId: string;
  status: ScanStatus;
  trigger: ScanTrigger;
  createdAt: string;
  startedAt: string | null;
  finishedAt: string | null;
  requestCount: number;
  baseUrl: string | null;
  error: string | null;
  findingCounts: SeverityCounts;
}

export interface ScanDetailDto extends ScanSummaryDto {
  domain: string;
  components: Array<{ type: SoftwareType; slug: string; name: string | null; version: string | null; versionConfidence: Confidence | null }>;
  modules: ModuleResult[];
}

type ScanRow = typeof scans.$inferSelect;
const iso = (d: Date | null) => (d ? d.toISOString() : null);
const emptyCounts = (): SeverityCounts => Object.fromEntries(SEVERITIES.map((s) => [s, 0])) as SeverityCounts;

function toSummary(row: ScanRow, counts: SeverityCounts = emptyCounts()): ScanSummaryDto {
  return {
    id: row.id,
    siteId: row.siteId,
    status: row.status,
    trigger: row.trigger,
    createdAt: row.createdAt.toISOString(),
    startedAt: iso(row.startedAt),
    finishedAt: iso(row.finishedAt),
    requestCount: row.requestCount,
    baseUrl: row.baseUrl,
    error: row.error,
    findingCounts: counts,
  };
}

/**
 * Scan requests and scan status. Finding details are deliberately not exposed yet: the
 * report phase adds them together with the free/paid visibility rules, so details can
 * never leak through an endpoint that predates those rules.
 */
export class ScanService {
  constructor(
    private readonly deps: { db: Database; ownership: OwnershipChecker; queue: ScanQueue; cooldownMinutes: number },
  ) {}

  private async ownedSite(ownerId: string, siteId: string) {
    const [site] = await this.deps.db
      .select({ id: sites.id, domain: sites.domain })
      .from(sites)
      .where(and(eq(sites.id, siteId), eq(sites.ownerId, ownerId)))
      .limit(1);
    if (!site) throw new HttpError(404, 'not_found', 'Site not found');
    return site;
  }

  private async counts(scanIds: string[]): Promise<Map<string, SeverityCounts>> {
    const result = new Map<string, SeverityCounts>();
    if (scanIds.length === 0) return result;
    const rows = await this.deps.db
      .select({ scanId: findings.scanId, severity: findings.severity, n: sql<number>`count(*)::int` })
      .from(findings)
      .where(inArray(findings.scanId, scanIds))
      .groupBy(findings.scanId, findings.severity);
    for (const r of rows) {
      if (!result.has(r.scanId)) result.set(r.scanId, emptyCounts());
      result.get(r.scanId)![r.severity] = r.n;
    }
    return result;
  }

  async request(ownerId: string, siteId: string, ctx: RequestContext): Promise<{ scan: ScanSummaryDto; retryAfter?: number }> {
    await this.ownedSite(ownerId, siteId);
    const result = await createScanRequest(this.deps.db, this.deps.ownership, {
      siteId,
      requestedBy: ownerId,
      trigger: 'manual',
      cooldownMinutes: this.deps.cooldownMinutes,
      ip: ctx.ip,
    });
    if (!result.ok) {
      const status = result.code === 'not_verified' ? 403 : result.code === 'in_progress' ? 409 : 429;
      const error = new HttpError(status, result.code === 'not_verified' ? 'ownership_not_verified' : result.code === 'in_progress' ? 'scan_in_progress' : 'scan_cooldown', result.message);
      Object.assign(error, { retryAfter: result.retryAfterSeconds });
      throw error;
    }
    try {
      await this.deps.queue.enqueue(result.scan.id);
    } catch {
      await markScanFailed(this.deps.db, result.scan.id, 'The scan could not be queued. Please try again.');
      throw new HttpError(503, 'queue_unavailable', 'Scanning is temporarily unavailable. Please try again shortly.');
    }
    return { scan: toSummary(result.scan) };
  }

  async listForSite(ownerId: string, siteId: string): Promise<ScanSummaryDto[]> {
    await this.ownedSite(ownerId, siteId);
    const rows = await this.deps.db.select().from(scans).where(eq(scans.siteId, siteId)).orderBy(desc(scans.createdAt)).limit(20);
    const counts = await this.counts(rows.map((r) => r.id));
    return rows.map((r) => toSummary(r, counts.get(r.id)));
  }

  async get(ownerId: string, scanId: string): Promise<ScanDetailDto> {
    const [row] = await this.deps.db
      .select({ scan: scans, domain: sites.domain })
      .from(scans)
      .innerJoin(sites, eq(sites.id, scans.siteId))
      .where(and(eq(scans.id, scanId), eq(sites.ownerId, ownerId)))
      .limit(1);
    if (!row) throw new HttpError(404, 'not_found', 'Scan not found');

    const components = await this.deps.db
      .select({
        type: siteComponents.softwareType,
        slug: siteComponents.slug,
        name: siteComponents.name,
        version: siteComponents.version,
        versionConfidence: siteComponents.versionConfidence,
      })
      .from(siteComponents)
      .where(eq(siteComponents.scanId, scanId))
      .orderBy(siteComponents.softwareType, siteComponents.slug);
    const counts = await this.counts([scanId]);

    return {
      ...toSummary(row.scan, counts.get(scanId)),
      domain: row.domain,
      components,
      modules: row.scan.moduleResults ?? [],
    };
  }
}
