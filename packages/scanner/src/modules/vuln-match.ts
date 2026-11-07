import { SEVERITIES, type Confidence, type Severity } from '@shc/shared';
import type { CheckModule, ComponentFact, Finding, Reference, VulnRecord } from '../types';
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
const rank = (s: Severity) => SEVERITIES.indexOf(s);

function displayName(c: ComponentFact): string {
  if (c.type === 'core') return 'WordPress';
  if (c.type === 'php') return 'PHP';
  return `${LABEL[c.type]} “${c.name ?? c.slug}”`;
}

/** A guessed version makes the match less certain; never more certain than the version. */
function matchConfidence(c: ComponentFact): Confidence {
  return c.versionConfidence ?? 'possible';
}

function severityOf(v: VulnRecord): Severity {
  if (v.informational) return 'info';
  return v.severity ?? severityFromCvss(v.cvssScore) ?? 'high';
}

function referencesOf(v: VulnRecord): Reference[] {
  return [
    ...(v.recordUrl ? [{ type: 'advisory' as const, id: `${v.source}:${v.sourceId}`, url: v.recordUrl }] : []),
    ...v.cveIds.map((id) => ({ type: 'cve' as const, id, url: `https://www.cve.org/CVERecord?id=${id}` })),
    ...v.references.filter((r) => r.url !== v.recordUrl),
  ];
}

/** PHP releases accumulate dozens of CVEs; one finding per runtime keeps the report readable. */
const GROUPED_TYPES = new Set(['php']);

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
      const matches: VulnRecord[] = [];
      for (const v of records) {
        if (!v.affected.some((range) => inRange(component.version!, range))) continue;
        const key = v.cveIds[0] ?? `${v.source}:${v.sourceId}`;
        if (seen.has(key)) continue;
        seen.add(key);
        matches.push(v);
      }
      if (matches.length === 0) continue;

      const ref = { type: component.type, slug: component.slug };
      if (GROUPED_TYPES.has(component.type)) {
        const ordered = [...matches].sort((a, b) => rank(severityOf(a)) - rank(severityOf(b)) || (b.cvssScore ?? 0) - (a.cvssScore ?? 0));
        findings.push({
          checkId: `vuln-match.${component.type}`,
          conceptId: 'exposure/known-vulnerable-component',
          severity: severityOf(ordered[0]!),
          title: `${displayName(component)} ${component.version} is affected by ${matches.length} known vulnerabilit${matches.length === 1 ? 'y' : 'ies'}`,
          confidence: matchConfidence(component),
          component: ref,
          references: ordered.slice(0, 10).flatMap(referencesOf).slice(0, 15),
          evidence: {
            detail: {
              installedVersion: component.version,
              count: matches.length,
              vulnerabilities: ordered.slice(0, 25).map((v) => ({ id: v.cveIds[0] ?? v.sourceId, title: v.title, severity: severityOf(v), fixedIn: v.fixedIn, source: v.source })),
            },
          },
        });
        continue;
      }

      for (const v of matches) {
        findings.push({
          checkId: `vuln-match.${v.source}`,
          conceptId: 'exposure/known-vulnerable-component',
          severity: severityOf(v),
          title: `${displayName(component)} ${component.version}: ${v.title}`,
          confidence: matchConfidence(component),
          component: ref,
          references: referencesOf(v),
          evidence: {
            detail: {
              component: component.slug,
              installedVersion: component.version,
              versionSource: component.sources,
              affected: v.affected,
              fixedIn: v.fixedIn,
              cvss: v.cvssScore,
              informational: v.informational ?? false,
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
