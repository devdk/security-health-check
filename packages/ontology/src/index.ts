import { EXPOSURES, type ExposureDef, type ExposureId } from './exposures';
import { ATTACK_PATTERNS, capecUrl, cweUrl, OWASP_TOP10_2021, WEAKNESSES, type AttackPatternId, type WeaknessId } from './standards';
import { GUIDES } from './guides';
import { COMPONENTS, CONTROLS, REMEDIATIONS, type ComponentId, type ControlId, type RemediationId } from './vocabulary';

export * from './exposures';
export * from './guides';
export * from './standards';
export * from './vocabulary';

/** Bump when concept ids are added, renamed or removed. Stored with each scan. */
export const ONTOLOGY_VERSION = '2026.11.2';

export type ConceptId = ExposureId | ComponentId | ControlId | RemediationId | WeaknessId | AttackPatternId;

export function isExposureId(id: string): id is ExposureId {
  return Object.hasOwn(EXPOSURES, id);
}

export function getExposure(id: ExposureId): ExposureDef {
  return EXPOSURES[id];
}

export interface FixGuide {
  id: RemediationId;
  title: string;
  summary: string;
  effort: 'minutes' | 'hour' | 'day';
  steps: readonly string[];
}

/** Structured fix guidance for an exposure, in the order it should be done. */
export function fixGuides(id: ExposureId): FixGuide[] {
  return EXPOSURES[id].remediatedBy.map((r) => ({ id: r, title: REMEDIATIONS[r].label, summary: REMEDIATIONS[r].summary, effort: REMEDIATIONS[r].effort, steps: GUIDES[r] }));
}

/**
 * Report text for a finding, derived entirely from the ontology: the explanation and the
 * fix steps (as markdown, stored with the finding as a snapshot).
 */
export function describeExposure(id: ExposureId): { explanation: string; fixSteps: string } {
  const guides = fixGuides(id);
  const fixSteps = guides
    .map((g) => [`**${g.title}.** ${g.summary}`, ...g.steps.map((s, i) => `${i + 1}. ${s}`)].join('\n'))
    .join('\n\n');
  return { explanation: EXPOSURES[id].description, fixSteps: fixSteps || 'No action needed.' };
}

/** Standard references for an exposure (CWE and CAPEC pages). */
export function standardReferences(id: ExposureId): Array<{ type: 'docs'; id: string; url: string }> {
  const e = EXPOSURES[id];
  return [
    ...e.weaknesses.map((w) => ({ type: 'docs' as const, id: w.replace('cwe/', 'CWE-'), url: cweUrl(w) })),
    ...e.enables.map((a) => ({ type: 'docs' as const, id: a.replace('capec/', 'CAPEC-'), url: capecUrl(a) })),
  ];
}

/** Every dangling reference in the ontology. Empty means consistent; enforced by tests. */
export function validateOntology(): string[] {
  const problems: string[] = [];
  const check = (owner: string, ids: readonly string[], table: object, what: string) => {
    for (const id of ids) if (!Object.hasOwn(table, id)) problems.push(`${owner}: unknown ${what} ${id}`);
  };
  for (const [id, e] of Object.entries(EXPOSURES) as Array<[ExposureId, ExposureDef]>) {
    check(id, e.appliesTo, COMPONENTS, 'component');
    check(id, e.weaknesses, WEAKNESSES, 'weakness');
    check(id, e.enables, ATTACK_PATTERNS, 'attack pattern');
    check(id, e.mitigatedBy, CONTROLS, 'control');
    check(id, e.remediatedBy, REMEDIATIONS, 'remediation');
    check(id, e.owasp, OWASP_TOP10_2021, 'OWASP category');
    if (e.kind === 'exposure' && e.remediatedBy.length === 0) problems.push(`${id}: exposure without a remediation`);
    if (e.appliesTo.length === 0) problems.push(`${id}: applies to no component`);
    if (e.detectedBy.length === 0) problems.push(`${id}: no detector`);
  }
  return problems;
}

const PREFIX = 'urn:shc:';

/**
 * JSON-LD export (SKOS labels plus our relations), so the vocabulary can be loaded into
 * graph tools or handed to an AI model as structured context.
 */
export function toJsonLd(): Record<string, unknown> {
  const ref = (id: string) => `shc:${id}`;
  const graph: Array<Record<string, unknown>> = [];

  for (const [id, label] of Object.entries(WEAKNESSES)) graph.push({ '@id': ref(id), '@type': 'Weakness', label, seeAlso: cweUrl(id as WeaknessId) });
  for (const [id, label] of Object.entries(ATTACK_PATTERNS)) graph.push({ '@id': ref(id), '@type': 'AttackPattern', label, seeAlso: capecUrl(id as AttackPatternId) });
  for (const [id, c] of Object.entries(COMPONENTS)) graph.push({ '@id': ref(id), '@type': 'Component', label: c.label, definition: c.description });
  for (const [id, c] of Object.entries(CONTROLS)) graph.push({ '@id': ref(id), '@type': 'Control', label: c.label, definition: c.description });
  for (const [id, r] of Object.entries(REMEDIATIONS)) {
    graph.push({ '@id': ref(id), '@type': 'Remediation', label: r.label, definition: r.summary, effort: r.effort, steps: [...GUIDES[id as RemediationId]] });
  }
  for (const [id, e] of Object.entries(EXPOSURES) as Array<[string, ExposureDef]>) {
    graph.push({
      '@id': ref(id),
      '@type': e.kind === 'exposure' ? 'Exposure' : 'Observation',
      label: e.label,
      definition: e.description,
      defaultSeverity: e.defaultSeverity,
      indicatesCompromise: e.indicatesCompromise ?? false,
      appliesTo: e.appliesTo.map(ref),
      hasWeakness: e.weaknesses.map(ref),
      enables: e.enables.map(ref),
      mitigatedBy: e.mitigatedBy.map(ref),
      remediatedBy: e.remediatedBy.map(ref),
      owaspTop10: [...e.owasp],
      detectedBy: [...e.detectedBy],
    });
  }

  const idRef = { '@type': '@id', '@container': '@set' };
  return {
    '@context': {
      shc: PREFIX,
      '@vocab': `${PREFIX}vocab#`,
      skos: 'http://www.w3.org/2004/02/skos/core#',
      rdfs: 'http://www.w3.org/2000/01/rdf-schema#',
      label: 'skos:prefLabel',
      definition: 'skos:definition',
      seeAlso: { '@id': 'rdfs:seeAlso', '@type': '@id' },
      appliesTo: idRef,
      hasWeakness: idRef,
      enables: idRef,
      mitigatedBy: idRef,
      remediatedBy: idRef,
    },
    '@id': `${PREFIX}ontology/${ONTOLOGY_VERSION}`,
    version: ONTOLOGY_VERSION,
    '@graph': graph,
  };
}
