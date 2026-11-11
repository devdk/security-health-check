#!/usr/bin/env node
/**
 * End-to-end scan against the local test WordPress. Development only.
 *
 *   docker compose --profile testwp up -d     (stack + test WordPress)
 *   node scripts/e2e-scan.mjs
 *
 * Signs up a throwaway user through the real API (via nginx), adds wordpress.test,
 * proves ownership with the file method, runs a scan, prints the result, and then
 * checks the test site's own access log to confirm the scanner kept to <= 2 requests
 * per second and always identified itself. Finally it pairs the companion plugin with
 * WP-CLI and checks the merged inside-plus-outside report.
 */
import { execFileSync } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const BASE = process.env.E2E_BASE_URL ?? 'http://localhost:8080';
const DOMAIN = 'wordpress.test';
// E2E_EMAIL / E2E_PASSWORD let you keep the account afterwards (e.g. to look around the dashboard).
const email = process.env.E2E_EMAIL ?? `e2e+${Date.now()}@example.com`;
const password = process.env.E2E_PASSWORD ?? `e2e-${Date.now()}-passphrase`;
let cookie = '';
let failures = 0;

const compose = (...args) => execFileSync('docker', ['compose', '--profile', 'testwp', ...args], { cwd: root, encoding: 'utf8' });
const psql = (statement) => compose('exec', '-T', 'postgres', 'psql', '-U', 'shc', '-d', 'shc', '-v', 'ON_ERROR_STOP=1', '-tAc', statement).trim();
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
// WP-CLI inside the test site's setup image, which mounts the companion plugin.
const wp = (...args) => compose('run', '--rm', '--no-deps', '-T', '--entrypoint', 'wp', 'testwp-setup', ...args);
const wpFails = (...args) => {
  try {
    wp(...args);
    return false;
  } catch {
    return true;
  }
};

function step(name, ok, detail = '') {
  if (!ok) failures++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? `  ->  ${detail}` : ''}`);
  return ok;
}

async function call(method, urlPath, body) {
  const res = await fetch(BASE + urlPath, {
    method,
    headers: { origin: BASE, ...(body ? { 'content-type': 'application/json' } : {}), ...(cookie ? { cookie } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  const setCookie = res.headers.get('set-cookie');
  if (setCookie) cookie = setCookie.split(';')[0];
  const text = await res.text();
  return { status: res.status, body: text ? JSON.parse(text) : null };
}

// 1. Account
const since = new Date().toISOString();
await call('POST', '/api/auth/register', { email, password });
await sleep(500);
const apiLog = compose('logs', 'api', '--no-log-prefix', '--since', since);
const verifyToken = [...apiLog.matchAll(/verify-email#token=([A-Za-z0-9_-]{43})/g)].at(-1)?.[1];
await call('POST', '/api/auth/verify-email', { token: verifyToken });
step('signed up and signed in', (await call('POST', '/api/auth/login', { email, password })).status === 200);

// 2. Site + ownership (file method, written straight into the test site's web root)
const added = await call('POST', '/api/sites', { domain: DOMAIN });
const site = added.body?.site;
if (!step('site added', added.status === 201, site?.domain)) process.exit(1);
const { filename, content } = site.instructions.file;
if (!/^shc-verify-[0-9a-f]{32}\.txt$/.test(filename) || !/^shc-verify=[0-9a-f]{32}$/.test(content)) throw new Error('unexpected token format');
compose('exec', '-T', 'testwp', 'sh', '-c', `printf '%s' '${content}' > /var/www/html/${filename}`);
const verified = await call('POST', `/api/sites/${site.id}/verify`, { method: 'file' });
if (!step('ownership verified by file', verified.body?.verified === true, verified.body?.message)) process.exit(1);

// 3. A sample vulnerability record so vuln-match has something to find before the real
//    feeds arrive (Phase 4). Removed again at the end.
const SAMPLE_ID = 'dev-sample:CVE-2020-35489';
psql(`insert into vuln_cache (source, source_id, software_type, slug, title, cve_ids, severity, affected, fixed_in, "references")
      values ('nvd', '${SAMPLE_ID}', 'plugin', 'contact-form-7', 'Unrestricted file upload (development sample record)',
              '{CVE-2020-35489}', 'critical', '[{"to":"5.3.1","toInclusive":true}]', '5.3.2',
              '[{"type":"advisory","url":"https://nvd.nist.gov/vuln/detail/CVE-2020-35489"}]')
      on conflict do nothing`);

try {
  // 4. Scan
  const started = await call('POST', `/api/sites/${site.id}/scans`, {});
  if (!step('scan queued', started.status === 202, started.body?.message ?? started.body?.scan?.status)) process.exit(1);
  const scanStart = new Date().toISOString();

  let scan;
  for (let i = 0; i < 120; i++) {
    await sleep(2000);
    scan = (await call('GET', `/api/scans/${started.body.scan.id}`)).body.scan;
    if (scan.status === 'completed' || scan.status === 'failed') break;
  }
  if (!step('scan finished', scan?.status === 'completed', scan?.error ?? scan?.status)) process.exit(1);

  const seconds = (Date.parse(scan.finishedAt) - Date.parse(scan.startedAt)) / 1000;
  console.log(`\n  ${scan.requestCount} requests in ${seconds.toFixed(1)}s against ${scan.baseUrl}`);
  for (const c of scan.components) console.log(`  - ${c.type.padEnd(7)} ${(c.name ?? c.slug).padEnd(28)} ${c.version ?? '?'} (${c.versionConfidence ?? 'n/a'})`);
  console.log(`  findings: ${JSON.stringify(scan.findingCounts)}`);
  console.log(`  modules:  ${scan.modules.map((m) => `${m.module}=${m.status}/${m.requests}req`).join(', ')}\n`);

  const by = (type, slug) => scan.components.find((c) => c.type === type && c.slug === slug);
  step('detected WordPress 6.4.2', by('core', 'wordpress')?.version === '6.4.2');
  step('detected Contact Form 7 5.3.1', by('plugin', 'contact-form-7')?.version === '5.3.1');
  step('detected the Twenty Twenty-One theme', by('theme', 'twentytwentyone')?.version === '2.0');
  step('detected PHP 8.1.27 from headers', by('php', 'php')?.version === '8.1.27');
  step('all twelve checks ran', scan.modules.length === 12 && scan.modules.every((m) => m.status === 'ok'), scan.modules.filter((m) => m.status !== 'ok').map((m) => `${m.module}=${m.status}`).join(', ') || 'all ok');
  // Critical: sample CF7 record + the planted wp-config.php.bak backup.
  step('flagged critical issues', scan.findingCounts.critical >= 2, JSON.stringify(scan.findingCounts));
  step('stayed under the request cap', scan.requestCount <= 150, String(scan.requestCount));

  const concepts = psql(`select string_agg(distinct concept_id, ',' order by concept_id) from findings where scan_id = '${scan.id}'`).split(',');
  for (const expected of [
    'exposure/config-backup-exposed',
    'exposure/debug-log-exposed',
    'exposure/php-unsupported',
    'exposure/xmlrpc-enabled',
    'exposure/usernames-via-rest-api',
    'exposure/https-not-enforced',
    'exposure/wordpress-core-outdated',
    'exposure/plugin-outdated',
  ]) {
    step(`found ${expected.replace('exposure/', '')}`, concepts.includes(expected));
  }
  const leaked = psql(`select count(*) from findings where scan_id = '${scan.id}' and (evidence::text like '%not-a-real-password%' or evidence::text like '%shc-admin%')`);
  step('no secrets or full usernames stored in evidence', leaked === '0');

  // Report: free view first.
  const freeRes = await fetch(`${BASE}/api/scans/${scan.id}/report`, { headers: { cookie } });
  const freeBody = await freeRes.text();
  const free = JSON.parse(freeBody).report;
  console.log(`\n  report: ${free.score}/100 grade ${free.grade}; free plan shows ${free.findings.length - free.lockedCount} of ${free.findings.length} findings`);
  step('report scored and graded', Number.isInteger(free.score) && /^[A-F]$/.test(free.grade), `${free.score} ${free.grade}`);
  step('free plan locks about two thirds', free.lockedCount > 0 && free.lockedCount < free.findings.length, `${free.lockedCount} locked`);
  const lockedOnly = free.findings.filter((f) => f.locked).every((f) => Object.keys(f).sort().join(',') === 'category,id,locked,severity');
  step('locked findings carry only severity and area', lockedOnly);
  const lockedTitles = psql(`select string_agg(title, '|') from findings where scan_id = '${scan.id}' and not visible_in_free and not indicates_compromise`).split('|');
  step('no locked title appears anywhere in the free response', lockedTitles.every((t) => t && !freeBody.includes(t)));
  const pdfFree = await fetch(`${BASE}/api/scans/${scan.id}/report.pdf`, { headers: { cookie } });
  step('PDF is refused on the free plan', pdfFree.status === 403);

  // Upgrade through the payment stub, then the full report and a real PDF.
  const up = await call('POST', '/api/billing/upgrade', { plan: 'pro' });
  step('upgraded to Pro (test-mode payment stub)', up.body?.billing?.plan === 'pro');
  const pro = (await call('GET', `/api/scans/${scan.id}/report`)).body.report;
  step('Pro sees every finding with fix guides', pro.lockedCount === 0 && pro.findings.every((f) => !f.locked && f.fix?.length > 0));
  step('NVD notice included for PHP data', pro.dataSources.some((d) => d.id === 'nvd' && /not endorsed or certified/.test(d.notice)));
  const pdfRes = await fetch(`${BASE}/api/scans/${scan.id}/report.pdf`, { headers: { cookie } });
  const pdf = Buffer.from(await pdfRes.arrayBuffer());
  const out = path.join(root, '.e2e', 'report.pdf');
  mkdirSync(path.dirname(out), { recursive: true });
  writeFileSync(out, pdf);
  step('PDF rendered by headless Chromium', pdfRes.status === 200 && pdf.subarray(0, 5).toString() === '%PDF-' && pdf.length > 20_000, `${Math.round(pdf.length / 1024)} KB -> ${path.relative(root, out)}`);

  // 5. Politeness, measured from the target's side: Apache's access log.
  const accessLog = compose('logs', 'testwp', '--no-log-prefix', '--since', scanStart);
  const requests = accessLog.split('\n').filter((l) => /"(GET|HEAD|POST|PUT|DELETE|OPTIONS|PATCH) /.test(l));
  const ours = requests.filter((l) => l.includes('SecurityHealthCheck/'));
  const perSecond = new Map();
  for (const line of ours) {
    const ts = /\[([^\]]+)\]/.exec(line)?.[1];
    if (ts) perSecond.set(ts, (perSecond.get(ts) ?? 0) + 1);
  }
  const peak = Math.max(0, ...perSecond.values());
  step('target saw at most 2 requests in any second', peak <= 2, `peak ${peak}/s over ${ours.length} logged requests`);
  const methods = new Set(ours.map((l) => /"([A-Z]+) /.exec(l)?.[1]));
  step('only GET/HEAD requests', [...methods].every((m) => m === 'GET' || m === 'HEAD'), [...methods].join(','));
  // requestCount also counts connection attempts that never reach the server (here: the
  // first HTTPS attempt, refused because the test site has no TLS).
  step(
    'every request that reached the site named the scanner',
    ours.length > 0 && ours.length === requests.length && ours.length <= scan.requestCount,
    `${ours.length} of ${requests.length} logged requests carried the SecurityHealthCheck User-Agent`,
  );

  // 6. Companion plugin: pair through the dashboard API and WP-CLI, then check the merged report.
  console.log('');
  const unsigned = await fetch(`${BASE}/api/plugin/reports`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' });
  step('unsigned plugin reports are refused', unsigned.status === 401, String(unsigned.status));

  const pairingRes = await call('POST', `/api/sites/${site.id}/plugin/pairing-code`, {});
  const pairing = pairingRes.body?.pairing;
  const pairingHint =
    pairingRes.body?.error === 'plugin_unavailable' ? 'PLUGIN_KEY_SECRET is not set: run npm run setup:env, then docker compose up -d api' : pairingRes.body?.message;
  if (!step('pairing code issued', /^[0-9A-Z]{5}-[0-9A-Z]{5}$/.test(pairing?.code ?? ''), pairing?.expiresAt ?? pairingHint)) process.exit(1);
  const pairedAt = new Date().toISOString();
  const pairOut = wp('shc', 'pair', pairing.code, '--service=http://web:8080');
  step('plugin paired from WP-CLI', /success/i.test(pairOut), pairOut.trim().split('\n').at(-1));
  const reuse = wpFails('shc', 'pair', pairing.code, '--service=http://web:8080');
  step('a pairing code works only once', reuse, 'second use refused');

  let status;
  for (let i = 0; i < 30; i++) {
    status = (await call('GET', `/api/sites/${site.id}/plugin`)).body?.plugin;
    if (status?.lastScanId && status.lastReportAt >= pairedAt) break;
    await sleep(1000);
  }
  step('dashboard shows the plugin connected', status?.status === 'connected' && Boolean(status.lastScanId), `plugin ${status?.pluginVersion}`);

  let inside;
  for (let i = 0; i < 60; i++) {
    inside = (await call('GET', `/api/scans/${status.lastScanId}`)).body.scan;
    if (inside.status === 'completed' || inside.status === 'failed') break;
    await sleep(1000);
  }
  step('inside report processed', inside?.status === 'completed' && inside.kind === 'inside', inside?.error ?? inside?.status);
  step('inside report sent no requests to the site', inside?.requestCount === 0, String(inside?.requestCount));

  const merged = (await call('GET', `/api/scans/${inside.id}/report`)).body.report;
  console.log(`\n  merged report: ${merged.score}/100 grade ${merged.grade}; ${merged.findings.length} findings`);
  step('report combines the outside scan and the inside report', merged.outside?.scanId === scan.id && merged.inside?.scanId === inside.id);
  const insideConcepts = new Set(merged.findings.filter((f) => f.source === 'inside').map((f) => f.conceptId));
  for (const expected of [
    'exposure/php-in-uploads',
    'exposure/core-files-modified',
    'exposure/suspicious-file-changes',
    'exposure/excessive-administrators',
    'exposure/no-two-factor-auth',
    'exposure/inactive-component-installed',
    'exposure/known-vulnerable-component',
    'exposure/plugin-outdated',
  ]) {
    step(`inside view found ${expected.replace('exposure/', '')}`, insideConcepts.has(expected));
  }
  const cf7Vulns = merged.findings.filter((f) => f.conceptId === 'exposure/known-vulnerable-component' && f.component?.slug === 'contact-form-7');
  step('inside versions replace outside guesses (no duplicate CF7 finding)', cf7Vulns.length === 1 && cf7Vulns[0].source === 'inside', cf7Vulns.map((f) => f.source).join(','));
  step('outside-only findings are kept', merged.findings.some((f) => f.source === 'outside' && f.conceptId === 'exposure/xmlrpc-enabled'));
  step('merged score is stored on the inside scan', inside.score === merged.score, `${inside.score} vs ${merged.score}`);
  step('silent index.php in uploads is not reported', !JSON.stringify(merged.findings).includes('uploads/index.php') && !JSON.stringify(merged.findings).includes('"index.php"'));

  const stored = psql(`select payload::text from plugin_reports where scan_id = '${inside.id}'`);
  step('stored report never holds full admin logins', !/shc-admin|shc-ops-/.test(stored) && /\*/.test(stored));

  await call('DELETE', `/api/sites/${site.id}/plugin`);
  step('after disconnecting, the plugin is refused', wpFails('shc', 'send'), 'send refused');
} finally {
  psql(`delete from vuln_cache where source_id = '${SAMPLE_ID}'`);
}

console.log(failures === 0 ? '\nAll end-to-end checks passed.' : `\n${failures} check(s) failed.`);
process.exit(failures === 0 ? 0 : 1);
