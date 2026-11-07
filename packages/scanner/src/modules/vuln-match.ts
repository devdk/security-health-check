import type { Confidence, Severity } from '@shc/shared';
import type { CheckModule, ComponentFact, Finding, Reference } from '../types';
import { inRange } from '../version';

export function severityFromCvss(score: number | null | undefined): Severity | null {
  if (score === null || score === undefined || Number.isNaN(score)) return null;
  if (score >= 9) return 'critical';
  if (score >= 7) return 'high';
  if (score >= 4) return 'medium';
  if (score > 0) return 'low';
  return 'info';
}

const LABEL: Record<string, string> = { core: 'WordPress', plugin: 'Plugin', theme: 'Theme', php: 'PHP', web_server: 'Web server' };

function displayName(c: ComponentFact): string {
  if (c.type === 'core') return 'WordPress';
  if (c.type === 'php') return 'PHP';
  return `${LABEL[c.type]} “${c.name ?? c.slug}”`;
}

/** A guessed version makes the match less certain; never more certain than the version. */
function matchConfidence(c: ComponentFact): Confidence {
  return c.versionConfidence ?? 'possible';
}

/**
 * Matches every versioned component found so far against the local vulnerability cache.
 * Makes no HTTP requests. The same CVE reported by several sources becomes one finding.
 */
export const vulnMatch: CheckModule = {
  id: 'vuln-match',
  title: 'Known vulnerabilities',
  stage: 2,

  async run(_target, ctx) {
    const findings: Finding[] = [];
    for (const component of ctx.components.list()) {
      if (!component.version || component.type === 'web_server') continue;
      const records = await ctx.vulns.forComponent(component.type, component.slug);
      const seen = new Set<string>();

      for (const v of records) {
        if (!v.affected.some((range) => inRange(component.version!, range))) continue;
        const key = v.cveIds[0] ?? `${v.source}:${v.sourceId}`;
        if (seen.has(key)) continue;
        seen.add(key);

        const references: Reference[] = [
          ...v.cveIds.map((id) => ({ type: 'cve' as const, id, url: `https://www.cve.org/CVERecord?id=${id}` })),
          ...v.references,
        ];
        findings.push({
          checkId: `vuln-match.${v.source}`,
          conceptId: 'exposure/known-vulnerable-component',
          severity: v.severity ?? severityFromCvss(v.cvssScore) ?? 'high',
          title: `${displayName(component)} ${component.version}: ${v.title}`,
          confidence: matchConfidence(component),
          component: { type: component.type, slug: component.slug },
          references,
          evidence: {
            detail: {
              component: component.slug,
              installedVersion: component.version,
              versionSource: component.sources,
              affected: v.affected,
              fixedIn: v.fixedIn,
              cvss: v.cvssScore,
              source: v.source,
              sourceId: v.sourceId,
            },
          },
        });
      }
    }
    return findings;
  },
};
