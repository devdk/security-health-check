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
 * per second and always identified itself.
 */
import { execFileSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const BASE = process.env.E2E_BASE_URL ?? 'http://localhost:8080';
const DOMAIN = 'wordpress.test';
const email = `e2e+${Date.now()}@example.com`;
const password = `e2e-${Date.now()}-passphrase`;
let cookie = '';
let failures = 0;

const compose = (...args) => execFileSync('docker', ['compose', '--profile', 'testwp', ...args], { cwd: root, encoding: 'utf8' });
const psql = (statement) => compose('exec', '-T', 'postgres', 'psql', '-U', 'shc', '-d', 'shc', '-v', 'ON_ERROR_STOP=1', '-tAc', statement).trim();
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

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
  step('flagged the vulnerable plugin', scan.findingCounts.critical >= 1);
  step('stayed under the request cap', scan.requestCount <= 150, String(scan.requestCount));

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
} finally {
  psql(`delete from vuln_cache where source_id = '${SAMPLE_ID}'`);
}

console.log(failures === 0 ? '\nAll end-to-end checks passed.' : `\n${failures} check(s) failed.`);
process.exit(failures === 0 ? 0 : 1);
