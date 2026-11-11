import { and, desc, eq, inArray } from 'drizzle-orm';
import { audit, loadReportParts, planFor } from '@shc/core';
import { findings, scans, serviceRequests, sites, type Database } from '@shc/db';
import { buildReportView, renderReportHtml, type ReportView } from '@shc/report';
import type { Plan } from '@shc/shared';
import { HttpError } from '../lib/errors';
import { PdfUnavailableError, type PdfRenderer } from '../lib/pdf';
import type { RequestContext } from './auth-service';

export const upgradeRequired = (what: string) => new HttpError(403, 'upgrade_required', `${what} is part of the Pro plan.`);

/**
 * Reports, PDF export and fix requests. Free/paid visibility is decided here, on the
 * server, through buildReportView; the dashboard only renders what it is sent.
 */
export class ReportService {
  constructor(private readonly deps: { db: Database; pdf: PdfRenderer }) {}

  private async ownedScan(ownerId: string, scanId: string) {
    const [row] = await this.deps.db
      .select({ scan: scans, domain: sites.domain })
      .from(scans)
      .innerJoin(sites, eq(sites.id, scans.siteId))
      .where(and(eq(scans.id, scanId), eq(sites.ownerId, ownerId)))
      .limit(1);
    if (!row) throw new HttpError(404, 'not_found', 'Scan not found');
    return row;
  }

  /** Free users keep the report of each site's most recent completed scan; history is Pro. */
  private async assertHistoryAllowed(plan: Plan, siteId: string, scanId: string): Promise<void> {
    if (plan === 'pro') return;
    const [latest] = await this.deps.db
      .select({ id: scans.id })
      .from(scans)
      .where(and(eq(scans.siteId, siteId), eq(scans.status, 'completed')))
      .orderBy(desc(scans.finishedAt))
      .limit(1);
    if (latest && latest.id !== scanId) throw upgradeRequired('Scan history');
  }

  async report(ownerId: string, scanId: string): Promise<ReportView> {
    const { db } = this.deps;
    const { scan, domain } = await this.ownedScan(ownerId, scanId);
    if (scan.status !== 'completed' || !scan.finishedAt) throw new HttpError(409, 'scan_not_finished', 'The report is ready once the scan has finished.');
    const plan = await planFor(db, ownerId);
    await this.assertHistoryAllowed(plan, scan.siteId, scan.id);

    const { part, counterpart } = await loadReportParts(db, { ...scan, finishedAt: scan.finishedAt });
    const ids = [...part.findings, ...(counterpart?.findings ?? [])].map((f) => f.id);
    const requests =
      plan === 'pro' && ids.length > 0
        ? await db
            .select({ findingId: serviceRequests.findingId, status: serviceRequests.status, createdAt: serviceRequests.createdAt })
            .from(serviceRequests)
            .where(and(eq(serviceRequests.userId, ownerId), inArray(serviceRequests.findingId, ids)))
        : [];

    return buildReportView(
      {
        ...part,
        scan: { ...part.scan, siteId: scan.siteId, status: scan.status, createdAt: scan.createdAt, startedAt: scan.startedAt, score: scan.score, grade: scan.grade },
        domain,
        counterpart,
        fixRequests: new Map(requests.filter((r) => r.findingId).map((r) => [r.findingId!, { status: r.status, createdAt: r.createdAt }])),
      },
      plan,
    );
  }

  async pdf(ownerId: string, scanId: string, ctx: RequestContext): Promise<{ pdf: Buffer; filename: string }> {
    if ((await planFor(this.deps.db, ownerId)) !== 'pro') throw upgradeRequired('PDF export');
    const view = await this.report(ownerId, scanId);
    let pdf: Buffer;
    try {
      pdf = await this.deps.pdf.render(renderReportHtml(view));
    } catch (err) {
      if (err instanceof PdfUnavailableError) throw new HttpError(503, 'pdf_unavailable', 'PDF export is temporarily unavailable. Please try again shortly.');
      throw err;
    }
    await audit(this.deps.db, { event: 'report_exported', userId: ownerId, siteId: view.siteId, ip: ctx.ip, meta: { scanId } });
    const date = (view.finishedAt ?? view.createdAt).slice(0, 10);
    return { pdf, filename: `security-report-${view.domain.replace(/[^a-z0-9.-]/gi, '_')}-${date}.pdf` };
  }

  /** "Request a fix": records a service request for a finding (Pro). One open request per finding. */
  async requestFix(ownerId: string, findingId: string, message: string, ctx: RequestContext) {
    const { db } = this.deps;
    if ((await planFor(db, ownerId)) !== 'pro') throw upgradeRequired('Requesting a fix');
    const [row] = await db
      .select({ findingId: findings.id, siteId: scans.siteId })
      .from(findings)
      .innerJoin(scans, eq(scans.id, findings.scanId))
      .innerJoin(sites, eq(sites.id, scans.siteId))
      .where(and(eq(findings.id, findingId), eq(sites.ownerId, ownerId)))
      .limit(1);
    if (!row) throw new HttpError(404, 'not_found', 'Finding not found');

    const [existing] = await db
      .select()
      .from(serviceRequests)
      .where(and(eq(serviceRequests.findingId, findingId), eq(serviceRequests.userId, ownerId), eq(serviceRequests.status, 'open')))
      .limit(1);
    if (existing) return { request: existing, created: false };

    const [request] = await db.insert(serviceRequests).values({ userId: ownerId, siteId: row.siteId, findingId, message }).returning();
    await audit(db, { event: 'fix_requested', userId: ownerId, siteId: row.siteId, ip: ctx.ip, meta: { findingId, requestId: request!.id } });
    return { request: request!, created: true };
  }
}
