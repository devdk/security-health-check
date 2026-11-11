import {
  ATTACK_PATTERNS,
  capecUrl,
  COMPONENTS,
  cweUrl,
  EXPOSURES,
  fixGuides,
  isExposureId,
  OWASP_TOP10_2021,
  WEAKNESSES,
  type ExposureDef,
} from '@shc/ontology';
import { SEVERITIES, type Confidence, type Plan, type ScanKind, type Severity, type SoftwareType } from '@shc/shared';
import { mergeParts, type FindingSource, type ScanPart, type SourcedFinding, type StoredComponent } from './merge';
import { computeScore, gradeFor, type Grade } from './score';

export interface Reference {
  type: 'cve' | 'advisory' | 'docs';
  id?: string;
  url?: string;
}

export interface StoredAttribution {
  source: string;
  recordUrl: string | null;
  copyrights: { message?: string; holders: Record<string, { notice: string; license: string; licenseUrl: string }> } | null;
}

/** A finding as stored, plus the component it concerns. */
export interface StoredFinding {
  id: string;
  checkId: string;
  conceptId: string;
  severity: Severity;
  confidence: Confidence;
  title: string;
  evidence: Record<string, unknown>;
  explanation: string;
  fixSteps: string;
  references: Reference[];
  indicatesCompromise: boolean;
  visibleInFree: boolean;
  sortOrder: number;
  component: { type: SoftwareType; slug: string; name: string | null; version: string | null } | null;
  attribution: StoredAttribution | null;
}

/** The scan the report was opened for, with its counterpart (see findCounterpart in @shc/core). */
export interface ReportInput extends ScanPart {
  scan: ScanPart['scan'] & {
    siteId: string;
    status: string;
    createdAt: Date;
    startedAt: Date | null;
    score: number | null;
    grade: string | null;
  };
  domain: string;
  counterpart: ScanPart | null;
  fixRequests?: Map<string, { status: string; createdAt: Date }>;
}

export interface FixGuideView {
  title: string;
  summary: string;
  effort: 'minutes' | 'hour' | 'day';
  steps: string[];
}

export interface RevealedFinding {
  id: string;
  locked: false;
  severity: Severity;
  confidence: Confidence;
  title: string;
  conceptId: string;
  category: string;
  explanation: string;
  evidence: Record<string, unknown>;
  /** Null when the fix guidance is locked for this plan. */
  fix: FixGuideView[] | null;
  fixLocked: boolean;
  fixNote: string | null;
  references: Reference[];
  standards: {
    weaknesses: Array<{ id: string; name: string; url: string }>;
    attackPatterns: Array<{ id: string; name: string; url: string }>;
    owasp: Array<{ id: string; name: string }>;
  };
  component: { type: SoftwareType; slug: string; name: string | null; version: string | null } | null;
  indicatesCompromise: boolean;
  attribution: { source: string; recordUrl: string | null; notices: string[] } | null;
  fixRequest: { status: string; createdAt: string } | null;
  source: FindingSource;
}

/** All a free user learns about a locked finding. Nothing from the scan beyond severity and area. */
export interface LockedFinding {
  id: string;
  locked: true;
  severity: Severity;
  category: string;
}

export type ReportFinding = RevealedFinding | LockedFinding;

export interface DataSource {
  id: 'wordfence' | 'nvd' | 'wordpress-org' | 'php-net';
  name: string;
  url: string;
  notice: string | null;
  licenses: Array<{ holder: string; notice: string; license: string; licenseUrl: string }>;
}

export interface ReportView {
  /** These fields, down to requestCount, describe the scan the report was opened for. */
  scanId: string;
  siteId: string;
  domain: string;
  status: string;
  createdAt: string;
  startedAt: string | null;
  finishedAt: string | null;
  baseUrl: string | null;
  requestCount: number;
  kind: ScanKind;
  outside: { scanId: string; finishedAt: string; baseUrl: string | null; requestCount: number } | null;
  inside: { scanId: string; finishedAt: string; pluginVersion: string | null } | null;
  plan: Plan;
  score: number;
  grade: Grade;
  counts: Record<Severity, number>;
  compromiseSuspected: boolean;
  lockedCount: number;
  findings: ReportFinding[];
  components: StoredComponent[];
  dataSources: DataSource[];
  features: { pdf: boolean; history: boolean; fixRequests: boolean; weeklyScans: boolean };
}

export const NVD_NOTICE = 'This product uses data from the NVD API but is not endorsed or certified by the NVD.';

/**
 * The area a finding concerns. When the finding names a piece of software, that wins
 * (a PHP vulnerability is about "PHP runtime", not the concept's first component).
 */
function categoryOf(conceptId: string, softwareType?: SoftwareType): string {
  if (!isExposureId(conceptId)) return 'Security issue';
  const applies = EXPOSURES[conceptId].appliesTo;
  if (softwareType) {
    const match = applies.find((c) => (COMPONENTS[c] as { softwareType?: string }).softwareType === softwareType);
    if (match) return COMPONENTS[match].label;
  }
  const first = applies[0];
  return first ? COMPONENTS[first].label : 'Security issue';
}

function standardsOf(conceptId: string): RevealedFinding['standards'] {
  if (!isExposureId(conceptId)) return { weaknesses: [], attackPatterns: [], owasp: [] };
  const e: ExposureDef = EXPOSURES[conceptId];
  return {
    weaknesses: e.weaknesses.map((w) => ({ id: w.replace('cwe/', 'CWE-'), name: WEAKNESSES[w], url: cweUrl(w) })),
    attackPatterns: e.enables.map((a) => ({ id: a.replace('capec/', 'CAPEC-'), name: ATTACK_PATTERNS[a], url: capecUrl(a) })),
    owasp: e.owasp.map((o) => ({ id: o, name: OWASP_TOP10_2021[o] })),
  };
}

function fixOf(conceptId: string): FixGuideView[] {
  if (!isExposureId(conceptId)) return [];
  return fixGuides(conceptId).map((g) => ({ title: g.title, summary: g.summary, effort: g.effort, steps: [...g.steps] }));
}

function fixNoteOf(f: StoredFinding): string | null {
  const detail = f.evidence.detail as Record<string, unknown> | undefined;
  const fixedIn = typeof detail?.fixedIn === 'string' ? detail.fixedIn : null;
  if (f.conceptId === 'exposure/known-vulnerable-component') {
    return fixedIn ? `Version ${fixedIn} or later fixes this.` : 'No fixed version has been published yet: remove or replace this software.';
  }
  const latest = typeof detail?.latest === 'string' ? detail.latest : null;
  return latest && /outdated/.test(f.conceptId) ? `The latest version is ${latest}.` : null;
}

function reveal(f: SourcedFinding, fixVisible: boolean, fixRequest: { status: string; createdAt: Date } | undefined): RevealedFinding {
  const holders = f.attribution?.copyrights?.holders ?? {};
  return {
    id: f.id,
    locked: false,
    severity: f.severity,
    confidence: f.confidence,
    title: f.title,
    conceptId: f.conceptId,
    category: categoryOf(f.conceptId, f.component?.type),
    explanation: f.explanation,
    evidence: f.evidence,
    fix: fixVisible ? fixOf(f.conceptId) : null,
    fixLocked: !fixVisible,
    fixNote: fixVisible ? fixNoteOf(f) : null,
    references: f.references,
    standards: standardsOf(f.conceptId),
    component: f.component,
    indicatesCompromise: f.indicatesCompromise,
    attribution: f.attribution
      ? { source: f.attribution.source, recordUrl: f.attribution.recordUrl, notices: Object.values(holders).map((h) => h.notice) }
      : null,
    fixRequest: fixRequest ? { status: fixRequest.status, createdAt: fixRequest.createdAt.toISOString() } : null,
    source: f.source,
  };
}

/** Built field by field on purpose: no stored value can slip through by accident. */
function lock(f: StoredFinding): LockedFinding {
  return { id: f.id, locked: true, severity: f.severity, category: categoryOf(f.conceptId, f.component?.type) };
}

function dataSourcesOf(revealed: RevealedFinding[], stored: Map<string, StoredFinding>): DataSource[] {
  const out: DataSource[] = [];
  const wordfence = revealed.filter((f) => f.attribution?.source === 'wordfence');
  if (wordfence.length > 0) {
    const licenses = new Map<string, DataSource['licenses'][number]>();
    for (const f of wordfence) {
      for (const [holder, h] of Object.entries(stored.get(f.id)?.attribution?.copyrights?.holders ?? {})) {
        if (!licenses.has(holder)) licenses.set(holder, { holder, ...h });
      }
    }
    out.push({ id: 'wordfence', name: 'Wordfence Intelligence', url: 'https://www.wordfence.com/threat-intel/', notice: null, licenses: [...licenses.values()] });
  }
  if (revealed.some((f) => f.attribution?.source === 'nvd')) {
    out.push({ id: 'nvd', name: 'National Vulnerability Database (NVD)', url: 'https://nvd.nist.gov/', notice: NVD_NOTICE, licenses: [] });
  }
  if (revealed.some((f) => /outdated/.test(f.conceptId))) {
    out.push({ id: 'wordpress-org', name: 'WordPress.org release information', url: 'https://wordpress.org/', notice: null, licenses: [] });
  }
  if (revealed.some((f) => f.conceptId === 'exposure/php-unsupported')) {
    out.push({ id: 'php-net', name: 'PHP supported versions (php.net)', url: 'https://www.php.net/supported-versions.php', notice: null, licenses: [] });
  }
  return out;
}

/**
 * The one place that decides what a user may see. The scan always runs in full; this
 * applies the plan at read time.
 *
 * Free: score, grade and counts; full detail for the findings chosen as visible when the
 * scan finished (about a third, mixed severities); possible-compromise findings always
 * show their title, explanation and evidence, but not the fix; everything else is locked.
 * Pro: everything, including fix guides.
 *
 * Findings, counts and the computed score cover the scan merged with its counterpart.
 */
export function buildReportView(input: ReportInput, plan: Plan): ReportView {
  const merged = mergeParts(input, input.counterpart);
  const ordered = merged.findings;
  const stored = new Map(ordered.map((f) => [f.id, f]));
  const pro = plan === 'pro';

  const findings: ReportFinding[] = ordered.map((f) => {
    const request = pro ? input.fixRequests?.get(f.id) : undefined;
    if (pro) return reveal(f, true, request);
    if (f.indicatesCompromise) return reveal(f, false, undefined);
    if (f.visibleInFree) return reveal(f, true, undefined);
    return lock(f);
  });

  const counts = Object.fromEntries(SEVERITIES.map((s) => [s, 0])) as Record<Severity, number>;
  for (const f of ordered) counts[f.severity]++;

  const computed = input.scan.score === null ? computeScore(ordered) : null;
  const score = input.scan.score ?? computed!.score;
  const revealed = findings.filter((f): f is RevealedFinding => !f.locked);

  return {
    scanId: input.scan.id,
    siteId: input.scan.siteId,
    domain: input.domain,
    status: input.scan.status,
    createdAt: input.scan.createdAt.toISOString(),
    startedAt: input.scan.startedAt?.toISOString() ?? null,
    finishedAt: input.scan.finishedAt.toISOString(),
    baseUrl: input.scan.baseUrl,
    requestCount: input.scan.requestCount,
    kind: input.scan.kind,
    outside: merged.outside && {
      scanId: merged.outside.scan.id,
      finishedAt: merged.outside.scan.finishedAt.toISOString(),
      baseUrl: merged.outside.scan.baseUrl,
      requestCount: merged.outside.scan.requestCount,
    },
    inside: merged.inside && {
      scanId: merged.inside.scan.id,
      finishedAt: merged.inside.scan.finishedAt.toISOString(),
      pluginVersion: merged.inside.scan.pluginVersion,
    },
    plan,
    score,
    grade: (input.scan.grade as Grade | null) ?? gradeFor(score),
    counts,
    // A heuristic ("possible") sign is listed as a finding but doesn't raise the alarm on its own.
    compromiseSuspected: ordered.some((f) => f.indicatesCompromise && f.confidence !== 'possible'),
    lockedCount: findings.filter((f) => f.locked).length,
    findings,
    components: merged.components,
    dataSources: dataSourcesOf(revealed, stored),
    features: { pdf: pro, history: pro, fixRequests: pro, weeklyScans: pro },
  };
}
