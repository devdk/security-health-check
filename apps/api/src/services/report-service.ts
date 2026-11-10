import { and, desc, eq, inArray } from 'drizzle-orm';
import { audit, planFor } from '@shc/core';
import { findings, scans, serviceRequests, siteComponents, sites, type Database } from '@shc/db';
import { buildReportView, renderReportHtml, type ReportView, type StoredFinding } from '@shc/report';
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
    if (scan.status !== 'completed') throw new HttpError(409, 'scan_not_finished', 'The report is ready once the scan has finished.');
    const plan = await planFor(db, ownerId);
    await this.assertHistoryAllowed(plan, scan.siteId, scan.id);

    const rows = await db
      .select({ f: findings, c: siteComponents })
      .from(findings)
      .leftJoin(siteComponents, eq(siteComponents.id, findings.componentId))
      .where(eq(findings.scanId, scanId))
      .orderBy(findings.sortOrder);
    const components = await db
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

    const ids = rows.map((r) => r.f.id);
    const requests =
      plan === 'pro' && ids.length > 0
        ? await db
            .select({ findingId: serviceRequests.findingId, status: serviceRequests.status, createdAt: serviceRequests.createdAt })
            .from(serviceRequests)
            .where(and(eq(serviceRequests.userId, ownerId), inArray(serviceRequests.findingId, ids)))
        : [];

    const stored: StoredFinding[] = rows.map(({ f, c }) => ({
      id: f.id,
      checkId: f.checkId,
      conceptId: f.conceptId,
      severity: f.severity,
      confidence: f.confidence,
      title: f.title,
      evidence: f.evidence as Record<string, unknown>,
      explanation: f.explanation,
      fixSteps: f.fixSteps,
      references: f.references,
      indicatesCompromise: f.indicatesCompromise,
      visibleInFree: f.visibleInFree,
      sortOrder: f.sortOrder,
      component: c ? { type: c.softwareType, slug: c.slug, name: c.name, version: c.version } : null,
      attribution: f.attribution ?? null,
    }));

    return buildReportView(
      {
        scan,
        domain,
        findings: stored,
        components,
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
