import { and, desc, eq, gte, lte, ne } from 'drizzle-orm';
import { findings, pluginReports, scans, siteComponents, type Executor } from '@shc/db';
import type { ScanPart, StoredFinding } from '@shc/report';

/** A counterpart older than this no longer describes the site the anchor saw. */
export const COUNTERPART_MAX_AGE_DAYS = 30;

type ScanRow = typeof scans.$inferSelect;

/** A completed scan, as far as pairing and loading need it. */
export type FinishedScan = Pick<ScanRow, 'id' | 'siteId' | 'kind' | 'baseUrl' | 'requestCount'> & { finishedAt: Date };

/**
 * The scan whose results are merged with `anchor`: the newest completed scan of the
 * other kind for the same site that finished at or before the anchor, at most
 * COUNTERPART_MAX_AGE_DAYS earlier. The worker and the API both pair scans here.
 */
export async function findCounterpart(db: Executor, anchor: Pick<FinishedScan, 'siteId' | 'kind' | 'finishedAt'>): Promise<FinishedScan | null> {
  const earliest = new Date(anchor.finishedAt.getTime() - COUNTERPART_MAX_AGE_DAYS * 86_400_000);
  const [row] = await db
    .select({ id: scans.id, siteId: scans.siteId, kind: scans.kind, baseUrl: scans.baseUrl, requestCount: scans.requestCount, finishedAt: scans.finishedAt })
    .from(scans)
    .where(
      and(
        eq(scans.siteId, anchor.siteId),
        ne(scans.kind, anchor.kind),
        eq(scans.status, 'completed'),
        lte(scans.finishedAt, anchor.finishedAt),
        gte(scans.finishedAt, earliest),
      ),
    )
    .orderBy(desc(scans.finishedAt))
    .limit(1);
  return row?.finishedAt ? { ...row, finishedAt: row.finishedAt } : null;
}

/** A scan's stored findings (with the component each concerns) and components. */
export async function loadScanPart(db: Executor, scan: FinishedScan): Promise<ScanPart> {
  const rows = await db
    .select({ f: findings, c: siteComponents })
    .from(findings)
    .leftJoin(siteComponents, eq(siteComponents.id, findings.componentId))
    .where(eq(findings.scanId, scan.id))
    .orderBy(findings.sortOrder);
  const components = await db
    .select({
      type: siteComponents.softwareType,
      slug: siteComponents.slug,
      name: siteComponents.name,
      version: siteComponents.version,
      versionConfidence: siteComponents.versionConfidence,
      active: siteComponents.active,
    })
    .from(siteComponents)
    .where(eq(siteComponents.scanId, scan.id))
    .orderBy(siteComponents.softwareType, siteComponents.slug);
  const [report] =
    scan.kind === 'inside'
      ? await db.select({ pluginVersion: pluginReports.pluginVersion }).from(pluginReports).where(eq(pluginReports.scanId, scan.id)).limit(1)
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

  return {
    scan: { id: scan.id, kind: scan.kind, finishedAt: scan.finishedAt, baseUrl: scan.baseUrl, requestCount: scan.requestCount, pluginVersion: report?.pluginVersion ?? null },
    findings: stored,
    components,
  };
}

/** What a merged report and score are built from: the scan's own part and its counterpart's. */
export async function loadReportParts(db: Executor, anchor: FinishedScan): Promise<{ part: ScanPart; counterpart: ScanPart | null }> {
  const other = await findCounterpart(db, anchor);
  const part = await loadScanPart(db, anchor);
  return { part, counterpart: other ? await loadScanPart(db, other) : null };
}
