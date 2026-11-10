import { describe, expect, it } from 'vitest';
import type { Severity } from '@shc/shared';
import { esc, renderReportHtml } from '../src/html';
import { computeScore, gradeFor } from '../src/score';
import { buildReportView, type StoredFinding } from '../src/view';
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
    const view = buildReportView({ scan, domain: 'example.com', findings: [finding(), finding()], components: [] }, 'pro');
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
    const view = buildReportView({ scan, domain: 'example.com', findings: [open, closed], components: [] }, 'free');

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
    const view = buildReportView({ scan, domain: 'example.com', findings: [hacked], components: [] }, 'free');
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

  it('labels the area by the affected software when there is one', () => {
    const php = finding({ conceptId: 'exposure/known-vulnerable-component', component: { type: 'php', slug: 'php', name: 'PHP', version: '8.1.27' } });
    const plugin = finding({ conceptId: 'exposure/known-vulnerable-component', component: { type: 'plugin', slug: 'x', name: 'X', version: '1' } });
    const view = buildReportView({ scan, domain: 'x', findings: [php, plugin], components: [] }, 'free');
    expect(view.findings.map((f) => f.category)).toEqual(['PHP runtime', 'Plugin']);
  });

  it('computes a score when the scan has none stored, and uses the stored one otherwise', () => {
    const findings = [finding({ severity: 'critical' })];
    expect(buildReportView({ scan, domain: 'x', findings, components: [] }, 'pro')).toMatchObject({ score: 49, grade: 'F' });
    expect(buildReportView({ scan: { ...scan, score: 88, grade: 'B' }, domain: 'x', findings, components: [] }, 'pro')).toMatchObject({ score: 88, grade: 'B' });
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
    const view = buildReportView({ scan, domain: 'x', findings: [wf, nvd], components: [] }, 'pro');
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
    expect(buildReportView({ scan, domain: 'x', findings: [finding({ visibleInFree: true }), wf], components: [] }, 'free').dataSources).toEqual([]);
  });
});

describe('report HTML', () => {
  it('escapes everything that came from the scanned site', () => {
    const evil = finding({ title: '<script>alert(1)</script>', evidence: { url: 'javascript:alert(1)', snippet: '<img src=x onerror=alert(1)>' } });
    const html = renderReportHtml(buildReportView({ scan, domain: '<b>x</b>', findings: [evil], components: [{ type: 'plugin', slug: 'x', name: '"><svg onload=alert(1)>', version: '1', versionConfidence: 'likely' }] }, 'pro'));
    expect(html).not.toContain('<script>alert');
    expect(html).not.toContain('<img src=x');
    expect(html).not.toContain('<svg onload');
    expect(html).not.toContain('href="javascript:');
    expect(html).toContain('&lt;script&gt;');
    expect(esc(`<"'&>`)).toBe('&lt;&quot;&#39;&amp;&gt;');
  });

  it('includes the score, fix guides and data-source notices, and no scripts', () => {
    const html = renderReportHtml(buildReportView({ scan, domain: 'example.com', findings: [finding({ attribution: { source: 'nvd', recordUrl: null, copyrights: null } })], components: [] }, 'pro'));
    expect(html).toMatch(/<div class="grade grade-[A-F]">/);
    expect(html).toContain('How to fix it');
    expect(html).toContain('not endorsed or certified by the NVD');
    expect(html).not.toMatch(/<script/i);
  });
});
