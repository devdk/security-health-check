import { eq } from 'drizzle-orm';
import { findings as findingsTable, scans, siteComponents, type Database } from '@shc/db';
import { describeExposure, EXPOSURES, standardReferences } from '@shc/ontology';
import type { ScanOutcome } from '@shc/scanner';
import { SEVERITIES } from '@shc/shared';

const severityRank = (s: string) => SEVERITIES.indexOf(s as (typeof SEVERITIES)[number]);

/**
 * Stores a finished scan in one transaction: the software found (site_components), the
 * findings linked to those components and to ontology concepts, and the scan summary.
 * Report text comes from the ontology so every finding explains itself.
 */
export async function saveOutcome(db: Database, scanId: string, siteId: string, outcome: ScanOutcome): Promise<void> {
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

    const ordered = [...outcome.findings].sort((a, b) => severityRank(a.severity) - severityRank(b.severity) || a.title.localeCompare(b.title));
    if (ordered.length > 0) {
      await tx.insert(findingsTable).values(
        ordered.map((f, index) => {
          const text = describeExposure(f.conceptId);
          const concept = EXPOSURES[f.conceptId];
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
            indicatesCompromise: 'indicatesCompromise' in concept && concept.indicatesCompromise === true,
            // Free/paid visibility is decided by the report phase.
            visibleInFree: false,
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
      })
      .where(eq(scans.id, scanId));
  });
}
