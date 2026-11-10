import { eq } from 'drizzle-orm';
import { findings as findingsTable, scans, siteComponents, type Database } from '@shc/db';
import { describeExposure, EXPOSURES, standardReferences, type ExposureDef } from '@shc/ontology';
import { computeScore, selectFreeVisible } from '@shc/report';
import type { ScanOutcome } from '@shc/scanner';
import { SEVERITIES } from '@shc/shared';

const severityRank = (s: string) => SEVERITIES.indexOf(s as (typeof SEVERITIES)[number]);

/**
 * Stores a finished scan in one transaction: the software found (site_components), the
 * findings linked to those components and to ontology concepts, which findings a free
 * user may see in full, and the score and grade.
 */
export async function saveOutcome(db: Database, scanId: string, siteId: string, outcome: ScanOutcome): Promise<{ score: number; grade: string }> {
  const ordered = [...outcome.findings]
    .map((f) => ({ ...f, indicatesCompromise: (EXPOSURES[f.conceptId] as ExposureDef).indicatesCompromise === true }))
    .sort((a, b) => severityRank(a.severity) - severityRank(b.severity) || a.title.localeCompare(b.title));
  const freeVisible = selectFreeVisible(ordered);
  const { score, grade } = computeScore(ordered);

  await db.transaction(async (tx) => {
    const componentIds = new Map<string, string>();
    if (outcome.components.length > 0) {
      const rows = await tx
        .insert(siteComponents)
        .values(
          outcome.components.map((c) => ({
            scanId,
            siteId,
            softwareType: c.type,
            slug: c.slug,
            name: c.name ?? null,
            version: c.version ?? null,
            versionConfidence: c.version ? (c.versionConfidence ?? 'possible') : null,
            sources: c.sources,
            active: c.active ?? null,
          })),
        )
        .returning({ id: siteComponents.id, type: siteComponents.softwareType, slug: siteComponents.slug });
      for (const r of rows) componentIds.set(`${r.type}:${r.slug}`, r.id);
    }

    if (ordered.length > 0) {
      await tx.insert(findingsTable).values(
        ordered.map((f, index) => {
          const text = describeExposure(f.conceptId);
          return {
            scanId,
            checkId: f.checkId,
            conceptId: f.conceptId,
            componentId: f.component ? (componentIds.get(`${f.component.type}:${f.component.slug}`) ?? null) : null,
            confidence: f.confidence,
            severity: f.severity,
            title: f.title,
            evidence: f.evidence,
            explanation: text.explanation,
            fixSteps: text.fixSteps,
            references: [...(f.references ?? []), ...standardReferences(f.conceptId)],
            indicatesCompromise: f.indicatesCompromise,
            visibleInFree: freeVisible.has(index),
            attribution: f.attribution ?? null,
            sortOrder: index,
          };
        }),
      );
    }

    await tx
      .update(scans)
      .set({
        status: 'completed',
        finishedAt: new Date(),
        requestCount: outcome.requestCount,
        baseUrl: outcome.baseUrl,
        moduleResults: outcome.modules,
        ontologyVersion: outcome.ontologyVersion,
        score,
        grade,
      })
      .where(eq(scans.id, scanId));
  });
  return { score, grade };
}
