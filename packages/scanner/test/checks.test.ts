import { describe, expect, it } from 'vitest';
import { ComponentStore } from '../src/components';
import { phpSupport, PHP_BRANCHES } from '../src/data/php-branches';
import { noReleases } from '../src/engine';
import {
  adminExposure,
  directoryListing,
  exposedFiles,
  outdatedSoftware,
  phpVersion,
  securityHeaders,
  tlsCheck,
  userEnum,
  vulnMatch,
  xmlrpc,
} from '../src/modules';
import { PoliteClient } from '../src/polite-client';
import { noRateLimit } from '../src/rate-limit';
import { FakeTlsProbe, FixtureFetcher, goodTls, memoryReleases, memoryVulns, noVulns, silentLog, type FixtureResponse } from '../src/testing';
import type { ReleaseLookup, ScanContext, VulnLookup, VulnRecord } from '../src/types';

const target = { domain: 'example.com', baseUrl: 'https://example.com' };
const url = (path: string) => `https://example.com${path}`;

function context(routes: Record<string, FixtureResponse>, opts: { vulns?: VulnLookup; releases?: ReleaseLookup; tls?: FakeTlsProbe } = {}) {
  const fetcher = new FixtureFetcher(routes);
  const http = PoliteClient.create({ fetcher, limiter: noRateLimit, domain: 'example.com', maxRequests: 150, tlsProbe: opts.tls });
  const ctx: ScanContext = { http, components: new ComponentStore(), vulns: opts.vulns ?? noVulns, releases: opts.releases ?? noReleases, log: silentLog };
  return { ctx, fetcher, http };
}

describe('php-version', () => {
  it('reads PHP from X-Powered-By, flags end-of-life branches and records the web server', async () => {
    const { ctx, http } = context({ [url('/')]: { headers: { 'x-powered-by': 'PHP/8.1.27', server: 'Apache/2.4.57 (Debian)' }, body: '<html></html>' } });
    const findings = await phpVersion.run(target, ctx);
    expect(ctx.components.get('php', 'php')).toMatchObject({ version: '8.1.27', versionConfidence: 'confirmed' });
    expect(ctx.components.get('web_server', 'apache')).toMatchObject({ version: '2.4.57' });
    expect(findings.map((f) => [f.conceptId, f.severity])).toEqual([
      ['exposure/php-version-disclosed', 'low'],
      ['exposure/php-unsupported', 'high'],
    ]);
    expect(findings[1]!.title).toBe('PHP 8.1 stopped receiving security fixes on 2025-12-31');
    expect(http.requestCount).toBe(1);
  });

  it('does not flag a supported branch, and stays quiet when PHP is hidden', async () => {
    const supported = context({ [url('/')]: { headers: { 'x-powered-by': 'PHP/8.4.3' } } });
    expect((await phpVersion.run(target, supported.ctx)).map((f) => f.conceptId)).toEqual(['exposure/php-version-disclosed']);
    const hidden = context({ [url('/')]: { headers: { server: 'nginx' } } });
    expect(await phpVersion.run(target, hidden.ctx)).toEqual([]);
    expect(hidden.ctx.components.get('web_server', 'nginx')).toMatchObject({ version: undefined });
  });
});

describe('PHP support data', () => {
  it('knows which branches are supported', () => {
    const today = new Date('2026-11-08T12:00:00Z');
    expect(phpSupport('8.1.27', today)).toMatchObject({ status: 'eol', securityUntil: '2025-12-31' });
    expect(phpSupport('8.2.10', today)).toMatchObject({ status: 'supported', daysLeft: 53 });
    expect(phpSupport('8.2.10', new Date('2027-01-01T00:00:01Z'))).toMatchObject({ status: 'eol' });
    expect(phpSupport('5.6.40', today)).toMatchObject({ status: 'eol' });
    expect(phpSupport('9.0.0', today)).toEqual({ status: 'unknown' });
  });

  it('is kept up to date (a new PHP branch ships every November)', () => {
    const newest = Date.parse(PHP_BRANCHES[0]!.released);
    const monthsOld = (Date.now() - newest) / (30 * 86_400_000);
    expect(monthsOld, `add the PHP branch released after ${PHP_BRANCHES[0]!.branch} to data/php-branches.ts`).toBeLessThan(15);
  });
});

describe('exposed-files', () => {
  it('finds sensitive files but never stores their contents', async () => {
    const { ctx, fetcher } = context({
      [url('/wp-config.php.bak')]: { headers: { 'content-type': 'application/octet-stream' }, body: "<?php\ndefine( 'DB_NAME', 'shop' );\ndefine( 'DB_PASSWORD', 'hunter2-secret' );" },
      [url('/.env')]: { headers: { 'content-type': 'text/plain' }, body: 'APP_KEY=abc\nDB_PASSWORD=hunter2-secret\n' },
      [url('/.git/HEAD')]: { headers: { 'content-type': 'text/plain' }, body: 'ref: refs/heads/main\n' },
      [url('/wp-content/debug.log')]: { headers: { 'content-type': 'text/plain' }, body: '[07-Nov-2026 10:00:00 UTC] PHP Warning:  Undefined variable $x in /var/www/html/x.php' },
      [url('/phpinfo.php')]: { headers: { 'content-type': 'text/html' }, body: '<html><head><title>phpinfo()</title></head><body>PHP Version 8.1.27</body></html>' },
      [url('/backup.zip')]: { headers: { 'content-type': 'application/zip' }, body: 'PK\u0003\u0004rest-of-zip' },
    });
    const findings = await exposedFiles.run(target, ctx);
    expect(findings.map((f) => `${f.severity} ${f.conceptId}`).sort()).toEqual([
      'critical exposure/config-backup-exposed',
      'critical exposure/env-file-exposed',
      'critical exposure/site-archive-exposed',
      'high exposure/debug-log-exposed',
      'high exposure/git-repository-exposed',
      'medium exposure/phpinfo-exposed',
    ]);
    expect(JSON.stringify(findings)).not.toContain('hunter2');
    // HEAD for every probe; GET only for the six that exist.
    const gets = fetcher.requested.filter((r) => r.startsWith('GET'));
    expect(gets).toHaveLength(6);
  });

  it('ignores "soft 404" pages that answer 200 for everything', async () => {
    const page = { headers: { 'content-type': 'text/html' }, body: '<!doctype html><html><body>Page not found. DB_PASSWORD CREATE TABLE PHP Warning:</body></html>' };
    const everything = new Proxy({} as Record<string, FixtureResponse>, { get: () => page });
    const fetcher = new FixtureFetcher(everything);
    const http = PoliteClient.create({ fetcher, limiter: noRateLimit, domain: 'example.com', maxRequests: 150 });
    const findings = await exposedFiles.run(target, { http, components: new ComponentStore(), vulns: noVulns, releases: noReleases, log: silentLog });
    expect(findings).toEqual([]);
    // HTML answers to HEAD are skipped without downloading anything (phpinfo probes excepted).
    expect(fetcher.requested.filter((r) => r.startsWith('GET')).every((r) => /php$/.test(r))).toBe(true);
  });

  it('falls back to a small GET when the server refuses HEAD', async () => {
    const { ctx } = context({ [url('/.env')]: { headStatus: 405, headers: { 'content-type': 'text/plain' }, body: 'APP_ENV=production\nDB_HOST=db' } });
    expect((await exposedFiles.run(target, ctx)).map((f) => f.conceptId)).toEqual(['exposure/env-file-exposed']);
  });
});

describe('user-enum', () => {
  it('reports usernames from the REST API and author archives, masked', async () => {
    const { ctx } = context({
      [url('/wp-json/wp/v2/users')]: { headers: { 'content-type': 'application/json; charset=UTF-8' }, body: JSON.stringify([{ id: 1, name: 'Admin', slug: 'shc-admin' }]) },
      [url('/?author=1')]: { status: 301, headers: { location: 'https://example.com/author/shc-admin/' } },
    });
    const findings = await userEnum.run(target, ctx);
    expect(findings.map((f) => f.conceptId)).toEqual(['exposure/usernames-via-rest-api', 'exposure/usernames-via-author-archives']);
    expect(findings[0]!.evidence.detail).toEqual({ count: 1, sample: ['s******n'] });
    expect(JSON.stringify(findings)).not.toContain('shc-admin');
  });

  it('reads author pages that answer directly instead of redirecting', async () => {
    const { ctx } = context({ [url('/?author=2')]: { body: '<html><body class="archive author author-editor-jo author-2">' } });
    const findings = await userEnum.run(target, ctx);
    expect(findings[0]).toMatchObject({ conceptId: 'exposure/usernames-via-author-archives', evidence: { detail: { count: 1 } } });
  });

  it('is quiet when both are locked down', async () => {
    const { ctx } = context({
      [url('/wp-json/wp/v2/users')]: { status: 401, headers: { 'content-type': 'application/json' }, body: '{"code":"rest_forbidden"}' },
      [url('/?author=1')]: { status: 404 },
    });
    expect(await userEnum.run(target, ctx)).toEqual([]);
  });
});

describe('xmlrpc', () => {
  it('spots a live endpoint from a plain GET', async () => {
    const { ctx } = context({ [url('/xmlrpc.php')]: { status: 405, body: 'XML-RPC server accepts POST requests only.' } });
    expect((await xmlrpc.run(target, ctx))[0]).toMatchObject({ conceptId: 'exposure/xmlrpc-enabled', confidence: 'likely' });
  });

  it('treats a blocked endpoint as fine', async () => {
    const { ctx } = context({ [url('/xmlrpc.php')]: { status: 403, body: 'Forbidden' } });
    expect(await xmlrpc.run(target, ctx)).toEqual([]);
  });
});

describe('directory-listing', () => {
  it('lists the folders that show their contents', async () => {
    const { ctx } = context({
      [url('/wp-content/uploads/')]: { body: '<html><head><title>Index of /wp-content/uploads</title></head><body><h1>Index of /wp-content/uploads</h1></body></html>' },
      [url('/wp-includes/')]: { body: '<html><head><title>Index of /wp-includes</title></head></html>' },
      [url('/wp-content/plugins/')]: { body: '' },
    });
    const [finding] = await directoryListing.run(target, ctx);
    expect(finding).toMatchObject({ conceptId: 'exposure/directory-listing-enabled', evidence: { detail: { directories: ['/wp-content/uploads/', '/wp-includes/'] } } });
  });
});

describe('tls', () => {
  const redirect = { [`http://example.com/`]: { status: 301, headers: { location: 'https://example.com/' } } };

  it('is quiet for a healthy setup, and counts handshakes as requests', async () => {
    const tls = new FakeTlsProbe({ 'example.com': { inspection: goodTls('example.com') } });
    const { ctx, http } = context(redirect, { tls });
    expect(await tlsCheck.run(target, ctx)).toEqual([]);
    expect(tls.calls).toEqual(['inspect example.com', 'legacy example.com']);
    expect(http.requestCount).toBe(3);
  });

  it.each([
    ['expired', goodTls('example.com', -3, { trusted: false, trustError: 'CERT_HAS_EXPIRED' }), 'exposure/tls-certificate-expired', /expired on/],
    ['expiring', goodTls('example.com', 10), 'exposure/tls-certificate-expiring-soon', /expires in 10 days/],
    ['self-signed', goodTls('example.com', 60, { trusted: false, trustError: 'DEPTH_ZERO_SELF_SIGNED_CERT' }), 'exposure/tls-certificate-invalid', /self-signed/],
    ['wrong name', goodTls('example.com', 60, { hostnameMatches: false }), 'exposure/tls-certificate-invalid', /does not cover example\.com/],
  ])('reports a %s certificate', async (_label, inspection, concept, title) => {
    const { ctx } = context(redirect, { tls: new FakeTlsProbe({ 'example.com': { inspection } }) });
    const findings = await tlsCheck.run(target, ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.conceptId).toBe(concept);
    expect(findings[0]!.title).toMatch(title);
  });

  it('reports legacy TLS and plain-HTTP pages', async () => {
    const tls = new FakeTlsProbe({ 'example.com': { inspection: goodTls('example.com'), legacy: true } });
    const { ctx } = context({ 'http://example.com/': { status: 200, body: '<html>' } }, { tls });
    expect((await tlsCheck.run(target, ctx)).map((f) => f.conceptId)).toEqual(['exposure/tls-legacy-protocol', 'exposure/https-not-enforced']);
  });

  it('reports a site with no HTTPS at all', async () => {
    const { ctx } = context({}, { tls: new FakeTlsProbe({}) });
    const findings = await tlsCheck.run({ domain: 'example.com', baseUrl: 'http://example.com' }, ctx);
    expect(findings).toEqual([expect.objectContaining({ conceptId: 'exposure/https-not-enforced', title: 'The site is not available over HTTPS' })]);
  });
});

describe('headers', () => {
  it('lists every missing browser protection', async () => {
    const { ctx } = context({ [url('/')]: { body: '<html>' } });
    const findings = await securityHeaders.run(target, ctx);
    expect(findings.map((f) => `${f.severity} ${f.conceptId}`)).toEqual([
      'low exposure/hsts-missing',
      'low exposure/csp-missing',
      'low exposure/clickjacking-protection-missing',
      'info exposure/mime-sniffing-protection-missing',
      'info exposure/referrer-policy-missing',
      'info exposure/permissions-policy-missing',
    ]);
  });

  it('accepts a well-configured site, including CSP frame-ancestors instead of X-Frame-Options', async () => {
    const { ctx } = context({
      [url('/')]: {
        headers: {
          'strict-transport-security': 'max-age=31536000; includeSubDomains',
          'content-security-policy': "default-src 'self'; frame-ancestors 'none'",
          'x-content-type-options': 'nosniff',
          'referrer-policy': 'strict-origin-when-cross-origin',
          'permissions-policy': 'camera=()',
        },
      },
      [url('/wp-login.php')]: { headers: { 'set-cookie': ['wordpress_test_cookie=WP%20Cookie%20check; path=/; secure'] }, body: '<form name="loginform">' },
    });
    expect(await securityHeaders.run(target, ctx)).toEqual([]);
  });

  it('flags session cookies without Secure, HttpOnly or SameSite, without keeping their values', async () => {
    const { ctx } = context({
      [url('/')]: { headers: { 'strict-transport-security': 'max-age=31536000', 'content-security-policy': "frame-ancestors 'self'", 'x-content-type-options': 'nosniff', 'referrer-policy': 'no-referrer', 'permissions-policy': 'camera=()' } },
      [url('/wp-login.php')]: { headers: { 'set-cookie': ['PHPSESSID=s3cr3tsess; path=/', 'wordpress_test_cookie=x; path=/'] } },
    });
    const findings = await securityHeaders.run(target, ctx);
    expect(findings).toEqual([expect.objectContaining({ conceptId: 'exposure/insecure-cookie-flags', evidence: expect.objectContaining({ detail: { cookies: [{ name: 'PHPSESSID', missing: ['Secure', 'HttpOnly', 'SameSite'] }] } }) })]);
    expect(JSON.stringify(findings)).not.toContain('s3cr3tsess');
  });
});

describe('admin-exposure', () => {
  const loginForm = '<form name="loginform" id="loginform" action="https://example.com/wp-login.php" method="post"><input id="user_login"></form>';

  it('reports an open login page with no visible protection', async () => {
    const { ctx } = context({
      [url('/wp-login.php')]: { body: loginForm },
      [url('/wp-admin/')]: { status: 302, headers: { location: 'https://example.com/wp-login.php?redirect_to=%2Fwp-admin%2F&reauth=1' } },
    });
    expect(await adminExposure.run(target, ctx)).toEqual([expect.objectContaining({ conceptId: 'exposure/login-unprotected', confidence: 'possible' })]);
  });

  it.each([
    ['a CAPTCHA', { [url('/wp-login.php')]: { body: `${loginForm}<div class="g-recaptcha"></div>` } }],
    ['a two-factor plugin', { [url('/wp-login.php')]: { body: `${loginForm}<script src="/wp-content/plugins/wordfence/modules/login-security/js/wfls-login.js"></script>` } }],
    ['wp-admin behind HTTP auth', { [url('/wp-login.php')]: { body: loginForm }, [url('/wp-admin/')]: { status: 401 } }],
    ['a moved login page', { [url('/wp-login.php')]: { status: 404 } }],
  ])('stays quiet with %s', async (_label, routes) => {
    const { ctx } = context(routes as Record<string, FixtureResponse>);
    expect(await adminExposure.run(target, ctx)).toEqual([]);
  });
});

describe('outdated-software', () => {
  it('compares versions with WordPress.org without touching the site', async () => {
    const releases = memoryReleases({
      core: { status: 'insecure', latest: '7.1.4' },
      latest: { 'plugin:contact-form-7': '6.1.2', 'theme:astra': '4.5.0' },
    });
    const { ctx, http } = context({}, { releases });
    ctx.components.add({ type: 'core', slug: 'wordpress', version: '6.4.2', versionConfidence: 'confirmed', sources: [] });
    ctx.components.add({ type: 'plugin', slug: 'contact-form-7', name: 'Contact Form 7', version: '5.3.1', versionConfidence: 'likely', sources: [] });
    ctx.components.add({ type: 'plugin', slug: 'premium', version: '1.0', sources: [] });
    ctx.components.add({ type: 'theme', slug: 'astra', version: '4.5.0', versionConfidence: 'confirmed', sources: [] });

    const findings = await outdatedSoftware.run(target, ctx);
    expect(findings.map((f) => [f.severity, f.title])).toEqual([
      ['high', 'WordPress 6.4.2 is missing security fixes (latest is 7.1.4)'],
      ['medium', 'Plugin “Contact Form 7” 5.3.1 is out of date (latest is 6.1.2)'],
    ]);
    expect(findings[1]!.confidence).toBe('likely');
    expect(http.requestCount).toBe(0);
  });
});

describe('vuln-match (PHP and attribution)', () => {
  const base: Pick<VulnRecord, 'source' | 'title' | 'cvssScore' | 'fixedIn' | 'references' | 'severity'> = {
    source: 'nvd',
    title: 't',
    cvssScore: null,
    fixedIn: null,
    references: [],
    severity: null,
  };

  it('groups PHP CVEs into one finding led by the worst one', async () => {
    const vulns = memoryVulns({
      'php:php': [
        { ...base, sourceId: 'CVE-1', cveIds: ['CVE-2024-0001'], cvssScore: 5.3, affected: [{ from: '8.1.0', to: '8.1.29', toInclusive: false }] },
        { ...base, sourceId: 'CVE-2', cveIds: ['CVE-2024-4577'], cvssScore: 9.8, affected: [{ from: '8.1.0', to: '8.1.29', toInclusive: false }], recordUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2024-4577' },
        { ...base, sourceId: 'CVE-3', cveIds: ['CVE-2023-0003'], cvssScore: 7.5, affected: [{ from: '8.2.0', to: '8.2.5' }] },
      ],
    });
    const { ctx } = context({}, { vulns });
    ctx.components.add({ type: 'php', slug: 'php', version: '8.1.27', versionConfidence: 'confirmed', sources: [] });
    const findings = await vulnMatch.run(target, ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ severity: 'critical', title: 'PHP 8.1.27 is affected by 2 known vulnerabilities', evidence: { detail: { count: 2 } } });
    expect(findings[0]!.references![0]).toEqual({ type: 'advisory', id: 'nvd:CVE-2', url: 'https://nvd.nist.gov/vuln/detail/CVE-2024-4577' });
  });

  it('downgrades informational records and links the source record first', async () => {
    const vulns = memoryVulns({
      'plugin:x': [{ ...base, source: 'wordfence', sourceId: 'uuid', cveIds: [], severity: 'high', informational: true, affected: [{ to: '2.0' }], recordUrl: 'https://www.wordfence.com/threat-intel/vulnerabilities/id/uuid' }],
    });
    const { ctx } = context({}, { vulns });
    ctx.components.add({ type: 'plugin', slug: 'x', version: '1.0', versionConfidence: 'likely', sources: [] });
    const [finding] = await vulnMatch.run(target, ctx);
    expect(finding!.severity).toBe('info');
    expect(finding!.references![0]!.url).toContain('wordfence.com');
  });
});
