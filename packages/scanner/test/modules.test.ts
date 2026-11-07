import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { ComponentStore } from '../src/components';
import { pluginsThemes, vulnMatch, wpDetect } from '../src/modules';
import { PoliteClient } from '../src/polite-client';
import { noRateLimit } from '../src/rate-limit';
import { FixtureFetcher, loadFixture, memoryVulns, noVulns, silentLog, type FixtureResponse } from '../src/testing';
import type { ScanContext, VulnLookup, VulnRecord } from '../src/types';

const fixture = (name: string) => loadFixture(path.join(import.meta.dirname, 'fixtures', name));
const target = { domain: 'example.com', baseUrl: 'https://example.com' };

function context(routes: Record<string, FixtureResponse>, vulns: VulnLookup = noVulns) {
  const fetcher = new FixtureFetcher(routes);
  const http = PoliteClient.create({ fetcher, limiter: noRateLimit, domain: 'example.com', maxRequests: 100 });
  const ctx: ScanContext = { http, components: new ComponentStore(), vulns, log: silentLog };
  return { ctx, fetcher, http };
}

describe('wp-detect', () => {
  it('confirms WordPress and its version from generator, feed and core assets', async () => {
    const { ctx, fetcher } = context(fixture('wp-classic').routes);
    const findings = await wpDetect.run(target, ctx);

    expect(ctx.components.get('core', 'wordpress')).toMatchObject({
      version: '6.4.2',
      versionConfidence: 'confirmed',
      sources: expect.arrayContaining(['wp-paths', 'rest-api-link', 'meta-generator', 'rss-feed', 'asset-version']),
    });
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      checkId: 'wp-detect.version-disclosed',
      conceptId: 'exposure/wordpress-version-disclosed',
      severity: 'low',
      confidence: 'confirmed',
      component: { type: 'core', slug: 'wordpress' },
    });
    expect(findings[0]!.evidence.snippet).toContain('WordPress 6.4.2');
    expect(fetcher.requested).toEqual(['GET https://example.com/', 'GET https://example.com/feed/']);
  });

  it('falls back to asset versions when the generator tag is removed', async () => {
    const { routes } = fixture('wp-classic');
    const home = routes['https://example.com/']!;
    const hidden: Record<string, FixtureResponse> = {
      ...routes,
      'https://example.com/': { ...home, body: home.body!.replace(/<meta name="generator"[^>]*>/g, '') },
    };
    delete hidden['https://example.com/feed/'];
    const { ctx } = context(hidden);
    const findings = await wpDetect.run(target, ctx);
    expect(ctx.components.get('core', 'wordpress')).toMatchObject({ version: '6.4.2', versionConfidence: 'likely' });
    expect(findings[0]?.confidence).toBe('likely');
  });

  it('notices a spoofed generator that disagrees with the assets', async () => {
    const { routes } = fixture('wp-classic');
    const home = routes['https://example.com/']!;
    const spoofed = {
      ...routes,
      'https://example.com/': { ...home, body: home.body!.replace('content="WordPress 6.4.2"', 'content="WordPress 9.9"') },
    };
    const { ctx } = context(spoofed);
    const [finding] = await wpDetect.run(target, ctx);
    // feed + assets (2 sources) outvote the generator tag (1 source)
    expect(ctx.components.get('core', 'wordpress')?.version).toBe('6.4.2');
    expect(finding?.confidence).toBe('likely');
    expect(finding?.evidence.detail?.otherVersionsSeen).toEqual(['9.9']);
  });

  it('reports a non-WordPress site as an observation only', async () => {
    const { ctx } = context({ 'https://example.com/': { body: '<html><head><title>Shop</title></head><body>Hello</body></html>' } });
    const findings = await wpDetect.run(target, ctx);
    expect(findings).toEqual([expect.objectContaining({ conceptId: 'observation/wordpress-not-detected', severity: 'info' })]);
    expect(ctx.components.list()).toEqual([]);
  });

  it('treats WordPress with no version anywhere as detected but unversioned', async () => {
    const { ctx } = context({ 'https://example.com/': { headers: { link: '<https://example.com/wp-json/>; rel="https://api.w.org/"' }, body: '<html></html>' } });
    const findings = await wpDetect.run(target, ctx);
    expect(findings).toEqual([]);
    expect(ctx.components.get('core', 'wordpress')).toMatchObject({ version: undefined, sources: ['rest-api-link'] });
  });
});

describe('plugins-themes', () => {
  it('fingerprints plugins and themes and reads their versions', async () => {
    const { ctx, http } = context(fixture('wp-classic').routes);
    const findings = await pluginsThemes.run(target, ctx);

    const plugins = Object.fromEntries(ctx.components.list('plugin').map((c) => [c.slug, c]));
    expect(Object.keys(plugins).sort()).toEqual(['contact-form-7', 'elementor', 'woocommerce']);
    expect(plugins['contact-form-7']).toMatchObject({ name: 'Contact Form 7', version: '5.3.1', versionConfidence: 'likely' });
    expect(plugins.woocommerce).toMatchObject({ version: '8.2.1', versionConfidence: 'likely' });
    // readme blocked: only the weak ?ver= hint remains
    expect(plugins.elementor).toMatchObject({ version: '3.17.3', versionConfidence: 'possible', sources: ['asset-path'] });

    const themes = Object.fromEntries(ctx.components.list('theme').map((c) => [c.slug, c]));
    expect(themes['astra-child']).toMatchObject({ name: 'Astra Child', version: '1.0.0', versionConfidence: 'confirmed' });
    expect(themes.astra).toMatchObject({ name: 'Astra', version: '4.5.0', versionConfidence: 'confirmed', sources: expect.arrayContaining(['style.css']) });

    expect(findings).toEqual([
      expect.objectContaining({ conceptId: 'exposure/component-versions-disclosed', severity: 'info', evidence: expect.objectContaining({ detail: expect.objectContaining({ total: 4 }) }) }),
    ]);
    // home + 3 readmes + 2 style.css
    expect(http.requestCount).toBe(6);
  });

  it('ignores slugs that are not plausible directory names', async () => {
    const html = `<link href="/wp-content/plugins/../../etc/passwd"><script src="/wp-content/plugins/good-plugin/x.js?ver=1.2"></script>`;
    const { ctx, fetcher } = context({ 'https://example.com/': { body: html } });
    await pluginsThemes.run(target, ctx);
    expect(ctx.components.list().map((c) => c.slug)).toEqual(['good-plugin']);
    expect(fetcher.requested.some((r) => r.includes('..'))).toBe(false);
  });
});

describe('vuln-match', () => {
  const cf7Vuln: VulnRecord = {
    source: 'wordfence',
    sourceId: 'cf7-upload',
    title: 'Unrestricted File Upload',
    cveIds: ['CVE-2020-35489'],
    cvssScore: null,
    severity: 'critical',
    affected: [{ from: '*', to: '5.3.1', toInclusive: true }],
    fixedIn: '5.3.2',
    references: [],
  };

  it('flags components whose version falls in an affected range', async () => {
    const vulns = memoryVulns({
      'plugin:contact-form-7': [cf7Vuln, { ...cf7Vuln, source: 'nvd', sourceId: 'CVE-2020-35489' }],
      'plugin:woocommerce': [{ ...cf7Vuln, sourceId: 'woo-old', cveIds: [], affected: [{ to: '8.0.0' }], severity: null, cvssScore: 6.1 }],
      'core:wordpress': [{ ...cf7Vuln, sourceId: 'core-1', cveIds: ['CVE-2099-0001'], title: 'Example core issue', affected: [{ from: '6.4', to: '6.4.3', toInclusive: false }], severity: null, cvssScore: 7.5 }],
    });
    const { ctx } = context({}, vulns);
    ctx.components.add({ type: 'core', slug: 'wordpress', version: '6.4.2', versionConfidence: 'confirmed', sources: [] });
    ctx.components.add({ type: 'plugin', slug: 'contact-form-7', name: 'Contact Form 7', version: '5.3.1', versionConfidence: 'likely', sources: ['readme.txt'] });
    ctx.components.add({ type: 'plugin', slug: 'woocommerce', version: '8.2.1', versionConfidence: 'likely', sources: [] });
    ctx.components.add({ type: 'plugin', slug: 'no-version', sources: [] });

    const findings = await vulnMatch.run(target, ctx);
    expect(findings).toHaveLength(2); // CF7 once (deduplicated by CVE) + core; WooCommerce 8.2.1 is outside its range
    const cf7 = findings.find((f) => f.component?.slug === 'contact-form-7')!;
    expect(cf7).toMatchObject({
      conceptId: 'exposure/known-vulnerable-component',
      severity: 'critical',
      confidence: 'likely',
      title: 'Plugin “Contact Form 7” 5.3.1: Unrestricted File Upload',
      references: [expect.objectContaining({ type: 'cve', id: 'CVE-2020-35489' })],
    });
    const core = findings.find((f) => f.component?.slug === 'wordpress')!;
    expect(core).toMatchObject({ severity: 'high', confidence: 'confirmed' }); // severity derived from CVSS 7.5
  });

  it('makes no HTTP requests', async () => {
    const { ctx, http } = context({});
    ctx.components.add({ type: 'plugin', slug: 'x', version: '1.0', sources: [] });
    await vulnMatch.run(target, ctx);
    expect(http.requestCount).toBe(0);
  });
});
