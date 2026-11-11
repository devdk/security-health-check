import { describe, expect, it } from 'vitest';
import type { Severity } from '@shc/shared';
import { esc, renderReportHtml } from '../src/html';
import { mergeParts, type ScanPart, type StoredComponent } from '../src/merge';
import { computeScore, gradeFor } from '../src/score';
import { buildReportView, type RevealedFinding, type StoredFinding } from '../src/view';
import { selectFreeVisible } from '../src/visibility';

let n = 0;
function finding(over: Partial<StoredFinding> = {}): StoredFinding {
  n++;
  return {
    id: `00000000-0000-0000-0000-${String(n).padStart(12, '0')}`,
    checkId: 'x.y',
    conceptId: 'exposure/xmlrpc-enabled',
    severity: 'medium',
    confidence: 'confirmed',
    title: `Secret title ${n}`,
    evidence: { url: 'https://example.com/xmlrpc.php', detail: { secretDetail: `detail-${n}` } },
    explanation: `Secret explanation ${n}`,
    fixSteps: 'stored',
    references: [],
    indicatesCompromise: false,
    visibleInFree: false,
    sortOrder: n,
    component: null,
    attribution: null,
    ...over,
  };
}

const scan = {
  id: 'scan-1',
  siteId: 'site-1',
  kind: 'external' as const,
  pluginVersion: null,
  status: 'completed',
  createdAt: new Date('2026-11-10T10:00:00Z'),
  startedAt: new Date('2026-11-10T10:00:01Z'),
  finishedAt: new Date('2026-11-10T10:00:30Z'),
  requestCount: 52,
  baseUrl: 'https://example.com',
  score: null,
  grade: null,
};

describe('computeScore', () => {
  const f = (severity: Severity, over: Partial<StoredFinding> = {}) => finding({ severity, conceptId: `exposure/${severity}-${n}`, ...over });

  it('gives a clean site 100 and an A', () => {
    expect(computeScore([])).toMatchObject({ score: 100, grade: 'A', cap: null });
    expect(computeScore([f('info'), f('info')]).score).toBe(100);
  });

  it('takes points off by severity and confidence', () => {
    expect(computeScore([f('medium')]).score).toBe(94);
    expect(computeScore([f('medium', { confidence: 'possible' })]).score).toBe(97);
    expect(computeScore([f('low'), f('low'), f('low')]).score).toBe(94);
  });

  it('counts repeats of the same problem less', () => {
    const same = [1, 2, 3, 4].map(() => finding({ severity: 'medium', conceptId: 'exposure/hsts-missing' }));
    // 6 + 3 + 1.5 + 1.5
    expect(computeScore(same).score).toBe(88);
  });

  it('caps the score for critical, high and possible-compromise findings', () => {
    expect(computeScore([f('high')])).toMatchObject({ score: 74, grade: 'C', cap: 'high' });
    expect(computeScore([f('critical')])).toMatchObject({ score: 49, grade: 'F', cap: 'critical' });
    expect(computeScore([f('critical', { confidence: 'possible' })]).cap).toBeNull();
    expect(computeScore([f('low', { indicatesCompromise: true })])).toMatchObject({ score: 19, grade: 'F', cap: 'compromise' });
    expect(computeScore([f('low', { indicatesCompromise: true, confidence: 'likely' })]).cap).toBe('compromise');
  });

  it('does not fail a site on a merely possible sign of compromise', () => {
    const heuristic = f('high', { indicatesCompromise: true, confidence: 'possible' });
    expect(computeScore([heuristic])).toMatchObject({ score: 93, grade: 'A', cap: null });
    expect(computeScore([heuristic, f('critical')])).toMatchObject({ cap: 'critical', grade: 'F' });
  });

  it('never goes below zero', () => {
    expect(computeScore(Array.from({ length: 10 }, () => f('critical'))).score).toBe(0);
  });

  it.each([
    [95, 'A'],
    [90, 'A'],
    [89, 'B'],
    [75, 'C'],
    [60, 'D'],
    [59, 'F'],
  ])('grade for %i is %s', (score, grade) => expect(gradeFor(score)).toBe(grade));
});

describe('selectFreeVisible', () => {
  const sev = (s: Severity, indicatesCompromise = false) => ({ severity: s, indicatesCompromise });

  it('shows about a third, spread across severities', () => {
    const list = [sev('critical'), sev('critical'), sev('high'), sev('high'), sev('medium'), sev('medium'), sev('low'), sev('low'), sev('info')];
    const chosen = [...selectFreeVisible(list)].map((i) => list[i]!.severity);
    expect(chosen).toEqual(['critical', 'high', 'medium']);
  });

  it('goes round again when one severity dominates', () => {
    const list = Array.from({ length: 7 }, () => sev('low'));
    expect(selectFreeVisible(list).size).toBe(3);
  });

  it('always shows at least one finding when there are any, and none when there are none', () => {
    expect(selectFreeVisible([sev('info')]).size).toBe(1);
    expect(selectFreeVisible([]).size).toBe(0);
  });

  it("leaves compromise indicators out of the allowance (they're always shown)", () => {
    const list = [sev('critical', true), sev('low'), sev('low'), sev('low')];
    expect([...selectFreeVisible(list)]).toEqual([1]);
  });
});

describe('buildReportView', () => {
  it('gives pro users every finding with fix guides', () => {
    const view = buildReportView({ scan, domain: 'example.com', findings: [finding(), finding()], components: [], counterpart: null }, 'pro');
    expect(view.lockedCount).toBe(0);
    expect(view.findings.every((f) => !f.locked && f.fix && f.fix.length > 0)).toBe(true);
    expect(view.features).toEqual({ pdf: true, history: true, fixRequests: true, weeklyScans: true });
  });

  it('locks everything a free user should not see, leaking nothing but severity and area', () => {
    const open = finding({ visibleInFree: true, severity: 'high', evidence: { url: 'https://example.com/open' } });
    const closed = finding({
      severity: 'critical',
      conceptId: 'exposure/config-backup-exposed',
      evidence: { url: 'https://example.com/LOCKED-EVIDENCE-PATH', detail: { secretDetail: 'LOCKED-DETAIL' } },
    });
    const view = buildReportView({ scan, domain: 'example.com', findings: [open, closed], components: [], counterpart: null }, 'free');

    expect(view.counts).toMatchObject({ high: 1, critical: 1 });
    expect(view.lockedCount).toBe(1);
    const locked = view.findings.find((f) => f.id === closed.id)!;
    expect(locked).toEqual({ id: closed.id, locked: true, severity: 'critical', category: 'Publicly served files' });
    const body = JSON.stringify(view);
    expect(body).not.toContain(closed.title);
    expect(body).not.toContain(closed.explanation);
    expect(body).not.toContain('LOCKED-DETAIL');
    expect(body).not.toContain('LOCKED-EVIDENCE-PATH');
    expect(body).toContain(open.title);
    expect(view.features.pdf).toBe(false);
  });

  it('always warns free users about possible compromise, but locks the fix', () => {
    const hacked = finding({ conceptId: 'exposure/php-in-uploads', severity: 'critical', indicatesCompromise: true });
    const view = buildReportView({ scan, domain: 'example.com', findings: [hacked], components: [], counterpart: null }, 'free');
    expect(view.compromiseSuspected).toBe(true);
    const shown = view.findings[0]!;
    expect(shown.locked).toBe(false);
    if (!shown.locked) {
      expect(shown.title).toBe(hacked.title);
      expect(shown.explanation).toBe(hacked.explanation);
      expect(shown.fix).toBeNull();
      expect(shown.fixLocked).toBe(true);
    }
  });

  it('lists a merely possible sign of compromise without raising the alarm', () => {
    const heuristic = finding({ conceptId: 'exposure/suspicious-file-changes', severity: 'high', confidence: 'possible', indicatesCompromise: true });
    const view = buildReportView({ scan, domain: 'example.com', findings: [heuristic], components: [], counterpart: null }, 'free');
    expect(view.compromiseSuspected).toBe(false);
    expect(view.findings[0]!.locked).toBe(false);
  });

  it('labels the area by the affected software when there is one', () => {
    const php = finding({ conceptId: 'exposure/known-vulnerable-component', component: { type: 'php', slug: 'php', name: 'PHP', version: '8.1.27' } });
    const plugin = finding({ conceptId: 'exposure/known-vulnerable-component', component: { type: 'plugin', slug: 'x', name: 'X', version: '1' } });
    const view = buildReportView({ scan, domain: 'x', findings: [php, plugin], components: [], counterpart: null }, 'free');
    expect(view.findings.map((f) => f.category)).toEqual(['PHP runtime', 'Plugin']);
  });

  it('computes a score when the scan has none stored, and uses the stored one otherwise', () => {
    const findings = [finding({ severity: 'critical' })];
    expect(buildReportView({ scan, domain: 'x', findings, components: [], counterpart: null }, 'pro')).toMatchObject({ score: 49, grade: 'F' });
    expect(buildReportView({ scan: { ...scan, score: 88, grade: 'B' }, domain: 'x', findings, components: [], counterpart: null }, 'pro')).toMatchObject({ score: 88, grade: 'B' });
  });

  it('carries attribution and the licences it requires', () => {
    const wf = finding({
      conceptId: 'exposure/known-vulnerable-component',
      evidence: { detail: { fixedIn: '5.3.2' } },
      attribution: {
        source: 'wordfence',
        recordUrl: 'https://www.wordfence.com/threat-intel/vulnerabilities/id/abc',
        copyrights: {
          holders: {
            defiant: { notice: 'Copyright 2012-2024 Defiant Inc.', license: 'Defiant licence text', licenseUrl: 'https://www.wordfence.com/wti-community-edition-terms-and-conditions/' },
            mitre: { notice: 'Copyright 1999-2024 The MITRE Corporation', license: 'MITRE licence text', licenseUrl: 'https://www.cve.org/Legal/TermsOfUse' },
          },
        },
      },
    });
    const nvd = finding({ conceptId: 'exposure/known-vulnerable-component', attribution: { source: 'nvd', recordUrl: null, copyrights: null } });
    const view = buildReportView({ scan, domain: 'x', findings: [wf, nvd], components: [], counterpart: null }, 'pro');
    const first = view.findings[0]!;
    if (!first.locked) {
      expect(first.attribution?.notices).toEqual(['Copyright 2012-2024 Defiant Inc.', 'Copyright 1999-2024 The MITRE Corporation']);
      expect(first.fixNote).toBe('Version 5.3.2 or later fixes this.');
    }
    expect(view.dataSources.map((d) => d.id)).toEqual(['wordfence', 'nvd']);
    expect(view.dataSources[0]!.licenses.map((l) => l.holder)).toEqual(['defiant', 'mitre']);
    expect(view.dataSources[1]!.notice).toMatch(/not endorsed or certified by the NVD/);
  });

  it('hides attribution of locked records from free users (they are not shown the data)', () => {
    const wf = finding({ attribution: { source: 'wordfence', recordUrl: 'https://www.wordfence.com/x', copyrights: null } });
    expect(buildReportView({ scan, domain: 'x', findings: [finding({ visibleInFree: true }), wf], components: [], counterpart: null }, 'free').dataSources).toEqual([]);
  });
});

describe('report HTML', () => {
  it('escapes everything that came from the scanned site', () => {
    const evil = finding({ title: '<script>alert(1)</script>', evidence: { url: 'javascript:alert(1)', snippet: '<img src=x onerror=alert(1)>' } });
    const html = renderReportHtml(buildReportView({ scan, domain: '<b>x</b>', findings: [evil], components: [{ type: 'plugin', slug: 'x', name: '"><svg onload=alert(1)>', version: '1', versionConfidence: 'likely', active: null }], counterpart: null }, 'pro'));
    expect(html).not.toContain('<script>alert');
    expect(html).not.toContain('<img src=x');
    expect(html).not.toContain('<svg onload');
    expect(html).not.toContain('href="javascript:');
    expect(html).toContain('&lt;script&gt;');
    expect(esc(`<"'&>`)).toBe('&lt;&quot;&#39;&amp;&gt;');
  });

  it('includes the score, fix guides and data-source notices, and no scripts', () => {
    const html = renderReportHtml(buildReportView({ scan, domain: 'example.com', findings: [finding({ attribution: { source: 'nvd', recordUrl: null, copyrights: null } })], components: [], counterpart: null }, 'pro'));
    expect(html).toMatch(/<div class="grade grade-[A-F]">/);
    expect(html).toContain('How to fix it');
    expect(html).toContain('not endorsed or certified by the NVD');
    expect(html).not.toMatch(/<script/i);
  });
});

describe('merged report', () => {
  const component = (type: StoredComponent['type'], slug: string, over: Partial<StoredComponent> = {}): StoredComponent => ({
    type,
    slug,
    name: slug,
    version: '1.0',
    versionConfidence: 'confirmed',
    active: null,
    ...over,
  });
  const about = (c: StoredComponent) => ({ type: c.type, slug: c.slug, name: c.name, version: c.version });
  const part = (kind: 'external' | 'inside', findings: StoredFinding[], components: StoredComponent[]): ScanPart => ({
    scan: {
      id: `${kind}-scan`,
      kind,
      finishedAt: new Date(kind === 'inside' ? '2026-11-10T09:00:00Z' : '2026-11-10T10:00:30Z'),
      baseUrl: 'https://example.com',
      requestCount: kind === 'inside' ? 0 : 52,
      pluginVersion: kind === 'inside' ? '0.1.0' : null,
    },
    findings,
    components,
  });

  const cf7Outside = component('plugin', 'contact-form-7', { version: '5.3.1', versionConfidence: 'likely' });
  const cf7Inside = component('plugin', 'contact-form-7', { version: '5.9', active: true });
  const elementor = component('plugin', 'elementor', { versionConfidence: 'possible' });
  const core = component('core', 'wordpress', { version: '6.4.2' });
  const nginx = component('web_server', 'nginx', { version: null, versionConfidence: null });

  it('lets the inside view replace outside findings it can see about software it lists', () => {
    const outdatedCf7 = finding({ conceptId: 'exposure/known-vulnerable-component', severity: 'critical', component: about(cf7Outside) });
    const outdatedCore = finding({ conceptId: 'exposure/wordpress-core-outdated', component: about(core) });
    const elementorVuln = finding({ conceptId: 'exposure/known-vulnerable-component', severity: 'high', component: about(elementor) });
    const coreDisclosed = finding({ conceptId: 'exposure/wordpress-version-disclosed', severity: 'low', component: about(core) });
    const cf7Readme = finding({ conceptId: 'exposure/component-versions-disclosed', severity: 'info', component: about(cf7Outside) });
    const unused = finding({ conceptId: 'exposure/inactive-component-installed', severity: 'low', component: about(cf7Inside) });

    const merged = mergeParts(
      part('external', [outdatedCf7, elementorVuln, outdatedCore, coreDisclosed, cf7Readme], [cf7Outside, elementor, core, nginx]),
      part('inside', [unused], [core, cf7Inside]),
    );
    expect(merged.findings.map((f) => [f.id, f.source])).toEqual([
      [elementorVuln.id, 'outside'],
      [coreDisclosed.id, 'outside'],
      [unused.id, 'inside'],
      [cf7Readme.id, 'outside'],
    ]);
    expect(merged.components).toEqual([core, cf7Inside, elementor, nginx]);
  });

  it('keeps outside version findings when the inside view lists the software without a version', () => {
    const outdated = finding({ conceptId: 'exposure/plugin-outdated', component: about(cf7Outside) });
    const versionless = component('plugin', 'contact-form-7', { version: null, active: true });
    const merged = mergeParts(part('external', [outdated], [cf7Outside]), part('inside', [], [versionless]));
    expect(merged.findings.map((f) => [f.id, f.source])).toEqual([[outdated.id, 'outside']]);
  });

  it('keeps every outside finding when there is no inside view', () => {
    const vuln = finding({ conceptId: 'exposure/known-vulnerable-component', component: about(cf7Outside) });
    expect(mergeParts(part('external', [vuln], [cf7Outside]), null).findings.map((f) => f.source)).toEqual(['outside']);
  });

  it('scores the merged findings, so a contradicted outside guess no longer counts', () => {
    const guess = finding({ conceptId: 'exposure/known-vulnerable-component', severity: 'critical', component: about(cf7Outside) });
    const outside = part('external', [guess], [cf7Outside]);
    const alone = buildReportView({ ...outside, scan: { ...scan, ...outside.scan }, domain: 'example.com', counterpart: null }, 'pro');
    expect(alone).toMatchObject({ score: 49, grade: 'F' });
    const merged = buildReportView({ ...outside, scan: { ...scan, ...outside.scan }, domain: 'example.com', counterpart: part('inside', [], [cf7Inside]) }, 'pro');
    expect(merged).toMatchObject({ score: 100, grade: 'A', counts: { critical: 0 } });
  });

  it('describes both parts and where each finding came from', () => {
    const outsideFinding = finding({ visibleInFree: true, severity: 'medium' });
    const insideFinding = finding({ conceptId: 'exposure/excessive-administrators', severity: 'low' });
    const inside = part('inside', [insideFinding], [cf7Inside]);
    const input = { ...inside, scan: { ...scan, ...inside.scan }, domain: 'example.com', counterpart: part('external', [outsideFinding], [elementor]) };

    const pro = buildReportView(input, 'pro');
    expect(pro).toMatchObject({
      scanId: 'inside-scan',
      kind: 'inside',
      outside: { scanId: 'external-scan', finishedAt: '2026-11-10T10:00:30.000Z', baseUrl: 'https://example.com', requestCount: 52 },
      inside: { scanId: 'inside-scan', finishedAt: '2026-11-10T09:00:00.000Z', pluginVersion: '0.1.0' },
    });
    expect(pro.findings.map((f) => (f as RevealedFinding).source)).toEqual(['outside', 'inside']);
    expect(pro.components.map((c) => [c.slug, c.active])).toEqual([
      ['contact-form-7', true],
      ['elementor', null],
    ]);

    const free = buildReportView(input, 'free');
    expect(free.findings[1]).toEqual({ id: insideFinding.id, locked: true, severity: 'low', category: 'User accounts' });

    const html = renderReportHtml(pro);
    expect(html).toContain('Outside scan 2026-11-10 10:00 UTC · 52 requests to https://example.com');
    expect(html).toContain('Inside view from the companion plugin 0.1.0, 2026-11-10 09:00 UTC');
    expect(html).toContain('<span class="src">Inside view</span>');
    expect(html).toContain('<span class="src">Outside scan</span>');
  });

  it('has no inside part for an outside scan without a counterpart', () => {
    const view = buildReportView({ scan, domain: 'x', findings: [finding()], components: [], counterpart: null }, 'pro');
    expect(view).toMatchObject({ kind: 'external', inside: null, outside: { scanId: 'scan-1', requestCount: 52 } });
  });
});
