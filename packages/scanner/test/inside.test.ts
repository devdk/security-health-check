import { describe, expect, it } from 'vitest';
import type { InsideReport } from '@shc/companion';
import { sampleInsideReport } from '@shc/companion/testing';
import { analyseInside } from '../src/inside';
import { memoryReleases, memoryVulns, noVulns } from '../src/testing';
import type { Finding, VulnLookup } from '../src/types';

/** The sample site with nothing to report: supported PHP and a two-factor plugin. */
function healthy(): InsideReport {
  const report = sampleInsideReport();
  report.php.version = '8.3.14';
  report.plugins.push({ slug: 'two-factor', file: 'two-factor/two-factor.php', name: 'Two Factor', version: '0.13.0', active: true, autoUpdate: true });
  return report;
}

const analyse = (report: InsideReport, vulns: VulnLookup = noVulns) => analyseInside(report, { vulns });
const ruleFindings = async (report: InsideReport) => (await analyse(report)).findings.filter((f) => f.checkId.startsWith('plugin.'));
const only = async (report: InsideReport, conceptId: string): Promise<Finding[]> => (await ruleFindings(report)).filter((f) => f.conceptId === conceptId);

describe('analyseInside', () => {
  it('finds nothing wrong with a healthy site and describes what is installed', async () => {
    const outcome = await analyse(healthy());
    expect(outcome.findings).toEqual([]);
    expect(outcome).toMatchObject({ baseUrl: 'https://example.com', requestCount: 0, ontologyVersion: expect.any(String) });
    expect(outcome.modules.map((m) => [m.module, m.status, m.requests])).toEqual([
      ['outdated-software', 'ok', 0],
      ['plugin', 'ok', 0],
      ['vuln-match', 'ok', 0],
    ]);
    expect(outcome.components).toEqual(
      expect.arrayContaining([
        { type: 'core', slug: 'wordpress', name: 'WordPress', version: '6.4.2', versionConfidence: 'confirmed', sources: ['plugin'] },
        { type: 'php', slug: 'php', name: 'PHP', version: '8.3.14', versionConfidence: 'confirmed', sources: ['plugin'] },
        { type: 'plugin', slug: 'contact-form-7', name: 'Contact Form 7', version: '5.3.1', versionConfidence: 'confirmed', sources: ['plugin'], active: true },
        { type: 'theme', slug: 'twentytwentyone', name: 'Twenty Twenty-One', version: '2.0', versionConfidence: 'confirmed', sources: ['plugin'], active: true },
      ]),
    );
    expect(outcome.components).toHaveLength(5);
  });

  it('reports the origin of the home URL as the base URL', async () => {
    const report = healthy();
    report.site.homeUrl = 'https://www.example.com/blog';
    expect((await analyse(report)).baseUrl).toBe('https://www.example.com');
  });

  it('flags a PHP branch that no longer gets security fixes', async () => {
    const report = healthy();
    report.php.version = '7.4.33';
    expect(await only(report, 'exposure/php-unsupported')).toEqual([
      expect.objectContaining({ checkId: 'plugin.php-unsupported', severity: 'high', confidence: 'confirmed', component: { type: 'php', slug: 'php' }, title: expect.stringMatching(/^PHP 7\.4 /) }),
    ]);
  });

  it('flags each inactive plugin and theme, but not the parent of the active child theme', async () => {
    const report = healthy();
    report.plugins.push({ slug: 'hello-dolly', file: 'hello.php', name: 'Hello Dolly', version: '1.7.2', active: false, autoUpdate: false });
    report.themes = [
      { slug: 'astra-child', name: 'Astra Child', version: '1.0.0', active: true, parent: 'astra', autoUpdate: false },
      { slug: 'astra', name: 'Astra', version: '4.5.0', active: false, parent: null, autoUpdate: false },
      { slug: 'twentytwentyfour', name: 'Twenty Twenty-Four', version: '1.2', active: false, parent: null, autoUpdate: false },
    ];
    const found = await only(report, 'exposure/inactive-component-installed');
    expect(found.map((f) => [f.component, f.severity, f.confidence])).toEqual([
      [{ type: 'plugin', slug: 'hello-dolly' }, 'low', 'confirmed'],
      [{ type: 'theme', slug: 'twentytwentyfour' }, 'low', 'confirmed'],
    ]);
    expect(found[0]!.title).toContain('Hello Dolly');
    expect(found[1]!.title).toContain('Twenty Twenty-Four');
  });

  it('flags missing two-factor sign-in when no known 2FA plugin is active', async () => {
    const report = healthy();
    report.plugins.find((p) => p.slug === 'two-factor')!.active = false;
    expect(await only(report, 'exposure/no-two-factor-auth')).toEqual([expect.objectContaining({ severity: 'medium', confidence: 'likely' })]);

    report.plugins.push({ slug: 'wp-2fa', file: 'wp-2fa/wp-2fa.php', name: 'WP 2FA', version: '2.8.0', active: true, autoUpdate: false });
    expect(await only(report, 'exposure/no-two-factor-auth')).toEqual([]);
  });

  it('flags more than three administrators, with masked logins capped at 20', async () => {
    const report = healthy();
    report.admins = Array.from({ length: 3 }, (_, i) => ({ login: `admin${i}`, roles: ['administrator'] }));
    expect(await only(report, 'exposure/excessive-administrators')).toEqual([]);

    report.admins = [{ login: 'shc-admin', roles: ['administrator'] }, ...Array.from({ length: 24 }, (_, i) => ({ login: `editor-${i}`, roles: ['administrator'] }))];
    const [finding] = await only(report, 'exposure/excessive-administrators');
    expect(finding).toMatchObject({ severity: 'low', confidence: 'confirmed', title: '25 accounts have full administrator rights' });
    const detail = finding!.evidence.detail as { count: number; logins: string[] };
    expect(detail.count).toBe(25);
    expect(detail.logins).toHaveLength(20);
    expect(detail.logins[0]).toBe('s******n');
    expect(JSON.stringify(finding)).not.toContain('shc-admin');
  });

  it('rates debug mode by whether errors reach visitors', async () => {
    const report = healthy();
    expect(await only(report, 'exposure/debug-mode-enabled')).toEqual([]);
    report.debug = { wpDebug: true, wpDebugDisplay: false, wpDebugLog: true, displayErrors: false };
    expect((await only(report, 'exposure/debug-mode-enabled'))[0]?.severity).toBe('low');
    report.debug.displayErrors = true;
    expect((await only(report, 'exposure/debug-mode-enabled'))[0]?.severity).toBe('medium');
    report.debug = { wpDebug: true, wpDebugDisplay: true, wpDebugLog: false, displayErrors: false };
    expect((await only(report, 'exposure/debug-mode-enabled'))[0]?.severity).toBe('medium');
  });

  it.each([
    ['0666', 'medium'],
    ['0660', 'medium'],
    ['0646', 'medium'],
    ['0644', 'low'],
    ['0604', 'low'],
    ['0640', null],
    ['0600', null],
    ['0400', null],
  ])('rates wp-config.php mode %s as %s', async (mode, severity) => {
    const report = healthy();
    report.configFile.mode = mode;
    const found = await only(report, 'exposure/config-file-permissions-weak');
    expect(found.map((f) => f.severity)).toEqual(severity ? [severity] : []);
  });

  it('skips the permission check where the host has no POSIX permissions', async () => {
    const report = healthy();
    report.configFile = { found: true, location: 'root', mode: null };
    expect(await only(report, 'exposure/config-file-permissions-weak')).toEqual([]);
  });

  it('flags changed or unexpected core files, listing at most 20 paths with totals', async () => {
    const report = healthy();
    report.coreIntegrity.modified = Array.from({ length: 30 }, (_, i) => `wp-includes/file-${i}.php`);
    report.coreIntegrity.unexpected = ['wp-admin/shell.php'];
    const [finding] = await only(report, 'exposure/core-files-modified');
    expect(finding).toMatchObject({ severity: 'critical', confidence: 'confirmed', title: '31 WordPress core files have been changed or added' });
    expect(finding!.evidence.detail).toMatchObject({ modifiedCount: 30, unexpectedCount: 1, unexpected: ['wp-admin/shell.php'] });
    expect((finding!.evidence.detail as { modified: string[] }).modified).toHaveLength(20);

    const unavailable = healthy();
    unavailable.coreIntegrity = { status: 'unavailable', reason: 'checksums could not be fetched', modified: [], missing: [], unexpected: [], truncated: false };
    expect(await only(unavailable, 'exposure/core-files-modified')).toEqual([]);
  });

  it('flags PHP files in uploads by path only', async () => {
    const report = healthy();
    report.uploadsPhp.files = [{ path: '2026/11/cache.php', size: 1234, modifiedAt: '2026-11-10T01:00:00Z' }];
    const [finding] = await only(report, 'exposure/php-in-uploads');
    expect(finding).toMatchObject({ severity: 'critical', confidence: 'confirmed', title: 'A PHP file was found in the uploads folder: 2026/11/cache.php' });
    expect(finding!.evidence).toEqual({ detail: { files: ['2026/11/cache.php'], count: 1, truncated: false, scanned: 12 } });
  });

  it('flags recent PHP changes that no update explains', async () => {
    const report = healthy();
    report.recentPhp.files = [{ path: 'plugins/contact-form-7/includes/form.php', modifiedAt: '2026-11-10T01:00:00Z', packageUpdated: true }];
    expect(await only(report, 'exposure/suspicious-file-changes')).toEqual([]);

    report.recentPhp.files.push({ path: 'themes/twentytwentyone/functions.php', modifiedAt: '2026-11-10T02:00:00Z', packageUpdated: false });
    const [finding] = await only(report, 'exposure/suspicious-file-changes');
    expect(finding).toMatchObject({ severity: 'high', confidence: 'possible' });
    expect(finding!.evidence.detail).toMatchObject({ files: ['themes/twentytwentyone/functions.php'], count: 1, days: 7 });
  });

  it('gives an exact count when a capped list still ends with update-explained files', async () => {
    const report = healthy();
    report.recentPhp.truncated = true;
    report.recentPhp.files = [
      { path: 'mu-plugins/loader.php', modifiedAt: '2026-11-10T02:00:00Z', packageUpdated: false },
      { path: 'plugins/contact-form-7/includes/form.php', modifiedAt: '2026-11-10T01:00:00Z', packageUpdated: true },
    ];
    const [exact] = await only(report, 'exposure/suspicious-file-changes');
    expect(exact!.title).toBe('A PHP file in wp-content changed in the last 7 days without an update: mu-plugins/loader.php');

    report.recentPhp.files = report.recentPhp.files.slice(0, 1);
    const [capped] = await only(report, 'exposure/suspicious-file-changes');
    expect(capped!.title).toBe('1+ PHP files in wp-content changed in the last 7 days without an update');
  });

  it('matches inactive plugins against vulnerability data too', async () => {
    const report = healthy();
    report.plugins[0]!.active = false;
    const vulns = memoryVulns({
      'plugin:contact-form-7': [
        { source: 'wordfence', sourceId: 'cf7', title: 'Unrestricted File Upload', cveIds: ['CVE-2020-35489'], cvssScore: 10, severity: 'critical', affected: [{ to: '5.3.1', toInclusive: true }], fixedIn: '5.3.2', references: [] },
      ],
    });
    const outcome = await analyse(report, vulns);
    const vuln = outcome.findings.find((f) => f.conceptId === 'exposure/known-vulnerable-component');
    expect(vuln).toMatchObject({ severity: 'critical', confidence: 'confirmed', component: { type: 'plugin', slug: 'contact-form-7' } });
    expect(vuln!.title).toContain('Contact Form 7');
  });

  it('checks every listed plugin and theme for newer releases, not just the first 40', async () => {
    const report = healthy();
    report.plugins = Array.from({ length: 60 }, (_, i) => ({ slug: `plugin-${i}`, file: `plugin-${i}/plugin-${i}.php`, name: `Plugin ${i}`, version: '1.0', active: true, autoUpdate: false }));
    const latest = Object.fromEntries(report.plugins.map((p) => [`plugin:${p.slug}`, '2.0']));
    const outcome = await analyseInside(report, { vulns: noVulns, releases: memoryReleases({ latest }) });
    expect(outcome.findings.filter((f) => f.conceptId === 'exposure/plugin-outdated')).toHaveLength(60);
  });

  it('compares reported versions with the latest releases', async () => {
    const outcome = await analyseInside(healthy(), { vulns: noVulns, releases: memoryReleases({ latest: { 'plugin:contact-form-7': '6.0.6' } }) });
    expect(outcome.findings).toEqual([expect.objectContaining({ conceptId: 'exposure/plugin-outdated', confidence: 'confirmed', component: { type: 'plugin', slug: 'contact-form-7' } })]);
  });

  it('leaves the companion plugin out', async () => {
    const report = healthy();
    report.plugins.push({ slug: 'shc-companion', file: 'shc-companion/shc-companion.php', name: 'Security Health Check Companion', version: '0.1.0', active: false, autoUpdate: false });
    const outcome = await analyse(report);
    expect(outcome.components.some((c) => c.slug === 'shc-companion')).toBe(false);
    expect(outcome.findings).toEqual([]);
  });

  it('records a failing check instead of failing the analysis', async () => {
    const broken: VulnLookup = { forComponent: async () => Promise.reject(new Error('cache offline')) };
    const outcome = await analyse(healthy(), broken);
    expect(outcome.modules.find((m) => m.module === 'vuln-match')).toMatchObject({ status: 'failed', findings: 0 });
    expect(outcome.modules.find((m) => m.module === 'plugin')?.status).toBe('ok');
  });
});
