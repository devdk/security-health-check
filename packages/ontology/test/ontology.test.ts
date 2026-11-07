import { describe, expect, it } from 'vitest';
import { SEVERITIES } from '@shc/shared';
import { describeExposure, EXPOSURES, isExposureId, standardReferences, toJsonLd, validateOntology, type ExposureId } from '../src/index';

const ids = Object.keys(EXPOSURES) as ExposureId[];

describe('ontology', () => {
  it('has no dangling references', () => {
    expect(validateOntology()).toEqual([]);
  });

  it('uses valid severities and well-formed ids', () => {
    for (const id of ids) {
      expect(id).toMatch(/^(exposure|observation)\/[a-z0-9-]+$/);
      expect(SEVERITIES).toContain(EXPOSURES[id].defaultSeverity);
    }
  });

  it('marks only critical/high exposures as compromise indicators', () => {
    for (const id of ids) {
      const e = EXPOSURES[id];
      if ('indicatesCompromise' in e && e.indicatesCompromise) expect(['critical', 'high']).toContain(e.defaultSeverity);
    }
  });

  it('covers every external check module in the build spec', () => {
    const modules = ['wp-detect', 'plugins-themes', 'vuln-match', 'php-version', 'exposed-files', 'user-enum', 'xmlrpc', 'directory-listing', 'tls', 'headers', 'admin-exposure'];
    const detectors = new Set(ids.flatMap((id) => EXPOSURES[id].detectedBy));
    for (const m of modules) expect(detectors, m).toContain(m);
  });

  it('builds default report text from the remediations', () => {
    const { explanation, fixSteps } = describeExposure('exposure/config-backup-exposed');
    expect(explanation).toMatch(/database password/);
    expect(fixSteps).toContain('**Remove the exposed file.**');
    expect(fixSteps).toContain('**Change the leaked secrets.**');
  });

  it('links CWE and CAPEC references', () => {
    expect(standardReferences('exposure/xmlrpc-enabled')).toEqual([
      { type: 'docs', id: 'CWE-307', url: 'https://cwe.mitre.org/data/definitions/307.html' },
      { type: 'docs', id: 'CAPEC-49', url: 'https://capec.mitre.org/data/definitions/49.html' },
    ]);
  });

  it('recognises exposure ids', () => {
    expect(isExposureId('exposure/xmlrpc-enabled')).toBe(true);
    expect(isExposureId('exposure/made-up')).toBe(false);
    expect(isExposureId('toString')).toBe(false);
  });

  it('exports JSON-LD where every reference resolves to a node', () => {
    const doc = toJsonLd() as { '@graph': Array<Record<string, unknown>> };
    const nodes = new Set(doc['@graph'].map((n) => n['@id']));
    for (const node of doc['@graph']) {
      for (const key of ['appliesTo', 'hasWeakness', 'enables', 'mitigatedBy', 'remediatedBy']) {
        for (const target of (node[key] as string[] | undefined) ?? []) expect(nodes, `${node['@id']} -> ${target}`).toContain(target);
      }
    }
  });
});
