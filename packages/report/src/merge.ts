import { EXPOSURES, isExposureId, type ExposureDef } from '@shc/ontology';
import { SEVERITIES, SOFTWARE_TYPES, type Confidence, type ScanKind, type SoftwareType } from '@shc/shared';
import type { StoredFinding } from './view';

export type FindingSource = 'outside' | 'inside';

export interface StoredComponent {
  type: SoftwareType;
  slug: string;
  name: string | null;
  version: string | null;
  versionConfidence: Confidence | null;
  /** Only the inside view knows; null for outside scans and for core and PHP. */
  active: boolean | null;
}

/** One completed scan's stored results. */
export interface ScanPart {
  scan: {
    id: string;
    kind: ScanKind;
    finishedAt: Date;
    baseUrl: string | null;
    requestCount: number;
    /** The companion plugin that sent the report, for inside scans. */
    pluginVersion: string | null;
  };
  findings: StoredFinding[];
  components: StoredComponent[];
}

export type SourcedFinding = StoredFinding & { source: FindingSource };

export interface MergedParts {
  outside: ScanPart | null;
  inside: ScanPart | null;
  findings: SourcedFinding[];
  components: StoredComponent[];
}

const SOURCE_ORDER: readonly FindingSource[] = ['outside', 'inside'];
const keyOf = (c: { type: SoftwareType; slug: string }) => `${c.type}:${c.slug}`;
const pluginCanSee = (conceptId: string) => isExposureId(conceptId) && (EXPOSURES[conceptId] as ExposureDef).detectedBy.includes('plugin');

/**
 * The site's picture from a scan and its counterpart. Where both views can see a
 * problem and the inside view lists the component it concerns with a version, the inside
 * view wins (it checks every listed component, so its silence means "not a problem"):
 * the outside finding is dropped, which removes outside version guesses the inside view
 * contradicts. The outside record of a component the inside view lists goes the same way.
 * Everything else from both scans is kept.
 */
export function mergeParts(part: ScanPart, counterpart: ScanPart | null): MergedParts {
  const parts = counterpart ? [part, counterpart] : [part];
  const outside = parts.find((p) => p.scan.kind === 'external') ?? null;
  const inside = parts.find((p) => p.scan.kind === 'inside') ?? null;
  const listedInside = new Set(inside?.components.map(keyOf));
  // Version-based findings need a version; without one the inside view knows no better.
  const versionedInside = new Set(inside?.components.filter((c) => c.version).map(keyOf));
  const superseded = (f: StoredFinding) => f.component !== null && versionedInside.has(keyOf(f.component)) && pluginCanSee(f.conceptId);

  const findings: SourcedFinding[] = [
    ...(outside?.findings.filter((f) => !superseded(f)).map((f) => ({ ...f, source: 'outside' as const })) ?? []),
    ...(inside?.findings.map((f) => ({ ...f, source: 'inside' as const })) ?? []),
  ].sort(
    (a, b) =>
      SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity) ||
      SOURCE_ORDER.indexOf(a.source) - SOURCE_ORDER.indexOf(b.source) ||
      a.sortOrder - b.sortOrder,
  );

  const components = [...(outside?.components.filter((c) => !listedInside.has(keyOf(c))) ?? []), ...(inside?.components ?? [])].sort(
    (a, b) => SOFTWARE_TYPES.indexOf(a.type) - SOFTWARE_TYPES.indexOf(b.type) || a.slug.localeCompare(b.slug),
  );

  return { outside, inside, findings, components };
}
