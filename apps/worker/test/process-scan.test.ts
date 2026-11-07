import path from 'node:path';
import { eq, sql } from 'drizzle-orm';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { auditEvents, createDb, findings, scans, siteComponents, sites, users, vulnCache, type DbHandle } from '@shc/db';
import type { OwnershipChecker, OwnershipResult } from '@shc/net';
import { noRateLimit, pluginsThemes, vulnMatch, wpDetect } from '@shc/scanner';
import { FakeTlsProbe, FixtureFetcher, goodTls, loadFixture, silentLog } from '@shc/scanner/testing';
import { failStuckScans, processScan, type ProcessDeps } from '../src/process-scan';
import { DbVulnLookup } from '@shc/intel';
import { workerTestDbUrl } from './global-setup';

const fixtureDir = path.resolve(import.meta.dirname, '../../../packages/scanner/test/fixtures/wp-classic');
const { routes } = loadFixture(fixtureDir);

class FakeOwnership implements OwnershipChecker {
  calls = 0;
  next: OwnershipResult = { ok: true, detail: 'ok' };
  async check(): Promise<OwnershipResult> {
    this.calls++;
    return this.next;
  }
}

let handle: DbHandle;
let ownership: FakeOwnership;
let fetcher: FixtureFetcher;
const log = { ...silentLog, error() {} };

function deps(overrides: Partial<ProcessDeps> = {}): ProcessDeps {
  return {
    db: handle.db,
    ownership,
    fetcher,
    limiter: noRateLimit,
    vulns: new DbVulnLookup(handle.db),
    // The detailed assertions below are about the first three checks; the full set is
    // covered by the scanner package and the end-to-end script.
    modules: [wpDetect, pluginsThemes, vulnMatch],
    scan: { maxRequests: 150, ratePerSecond: 2, cooldownMinutes: 0, concurrency: 1, timeoutSeconds: 30 },
    log,
    ...overrides,
  };
}

async function queuedScan(opts: { verifiedHoursAgo?: number | null } = {}) {
  const [user] = await handle.db.insert(users).values({ email: `owner${Date.now()}${Math.random()}@example.com`, passwordHash: 'x' }).returning();
  const verifiedAt = opts.verifiedHoursAgo === null ? null : new Date(Date.now() - (opts.verifiedHoursAgo ?? 1) * 3600_000);
  const [site] = await handle.db
    .insert(sites)
    .values({ ownerId: user!.id, domain: 'example.com', verificationToken: 'a'.repeat(32), verifiedAt, verificationMethod: verifiedAt ? 'dns_txt' : null })
    .returning();
  const [scan] = await handle.db.insert(scans).values({ siteId: site!.id, requestedBy: user!.id, kind: 'external', trigger: 'manual' }).returning();
  return { user: user!, site: site!, scan: scan! };
}

beforeAll(() => {
  handle = createDb(workerTestDbUrl(), { max: 3 });
});
afterAll(async () => {
  await handle.close();
});
beforeEach(async () => {
  await handle.db.execute(sql`truncate table users, vuln_cache restart identity cascade`);
  ownership = new FakeOwnership();
  fetcher = new FixtureFetcher(routes);
});

describe('processScan', () => {
  it('runs a queued scan and stores components, typed findings and a summary', async () => {
    await handle.db.insert(vulnCache).values({
      source: 'wordfence',
      sourceId: 'cf7-5.3.1',
      softwareType: 'plugin',
      slug: 'contact-form-7',
      title: 'Unrestricted File Upload',
      cveIds: ['CVE-2020-35489'],
      severity: 'critical',
      affected: [{ to: '5.3.1', toInclusive: true }],
      fixedIn: '5.3.2',
    });
    const { scan } = await queuedScan();

    expect(await processScan(scan.id, deps())).toBe('completed');

    const [saved] = await handle.db.select().from(scans).where(eq(scans.id, scan.id));
    expect(saved).toMatchObject({ status: 'completed', baseUrl: 'https://example.com', requestCount: 7, error: null });
    expect(saved!.ontologyVersion).toBeTruthy();
    expect(saved!.moduleResults?.map((m) => m.status)).toEqual(['ok', 'ok', 'ok']);

    const components = await handle.db.select().from(siteComponents).where(eq(siteComponents.scanId, scan.id));
    expect(components.map((c) => `${c.softwareType}:${c.slug}@${c.version}`).sort()).toEqual([
      'core:wordpress@6.4.2',
      'plugin:contact-form-7@5.3.1',
      'plugin:elementor@3.17.3',
      'plugin:woocommerce@8.2.1',
      'theme:astra-child@1.0.0',
      'theme:astra@4.5.0',
    ]);

    const rows = await handle.db.select().from(findings).where(eq(findings.scanId, scan.id)).orderBy(findings.sortOrder);
    expect(rows.map((f) => [f.severity, f.conceptId])).toEqual([
      ['critical', 'exposure/known-vulnerable-component'],
      ['low', 'exposure/wordpress-version-disclosed'],
      ['info', 'exposure/component-versions-disclosed'],
    ]);
    const vuln = rows[0]!;
    const cf7 = components.find((c) => c.slug === 'contact-form-7')!;
    expect(vuln.componentId).toBe(cf7.id);
    expect(vuln.explanation).toMatch(/publicly documented vulnerability/);
    expect(vuln.fixSteps).toContain('**Update the affected software.**');
    expect(vuln.references).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ type: 'cve', id: 'CVE-2020-35489' }),
        expect.objectContaining({ id: 'CWE-1395' }),
      ]),
    );
    expect(rows.every((f) => f.visibleInFree === false && f.indicatesCompromise === false)).toBe(true);

    const events = (await handle.db.select().from(auditEvents)).map((e) => e.event);
    expect(events).toContain('scan_completed');
  });

  it('re-checks stale ownership itself and refuses to scan when it fails', async () => {
    const { scan } = await queuedScan({ verifiedHoursAgo: 30 });
    ownership.next = { ok: false, reason: 'TXT record removed' };

    expect(await processScan(scan.id, deps())).toBe('failed');
    expect(ownership.calls).toBe(1);
    expect(fetcher.requested).toEqual([]); // the site was never contacted
    const [saved] = await handle.db.select().from(scans).where(eq(scans.id, scan.id));
    expect(saved).toMatchObject({ status: 'failed' });
    expect(saved!.error).toMatch(/TXT record removed/);
  });

  it('never scans a site that was never verified', async () => {
    const { scan } = await queuedScan({ verifiedHoursAgo: null });
    expect(await processScan(scan.id, deps())).toBe('failed');
    expect(fetcher.requested).toEqual([]);
  });

  it('records an unreachable site as a clear failure', async () => {
    const { scan } = await queuedScan();
    fetcher = new FixtureFetcher({ 'https://example.com/': { error: 'connect_failed' }, 'http://example.com/': { error: 'connect_failed' } });
    expect(await processScan(scan.id, deps())).toBe('failed');
    const [saved] = await handle.db.select().from(scans).where(eq(scans.id, scan.id));
    expect(saved!.error).toMatch(/couldn't reach example\.com/);
  });

  it('runs the full set of checks and stores every finding with its ontology text', async () => {
    const { scan } = await queuedScan();
    const result = await processScan(scan.id, deps({ modules: undefined, tlsProbe: new FakeTlsProbe({ 'example.com': { inspection: goodTls('example.com') } }) }));
    expect(result).toBe('completed');
    const [saved] = await handle.db.select().from(scans).where(eq(scans.id, scan.id));
    expect(saved!.moduleResults).toHaveLength(12);
    expect(saved!.moduleResults!.every((m) => m.status === 'ok')).toBe(true);
    const rows = await handle.db.select().from(findings).where(eq(findings.scanId, scan.id));
    expect(rows.length).toBeGreaterThan(3);
    expect(rows.every((f) => f.explanation.length > 20 && f.fixSteps.includes('**'))).toBe(true);
    const php = await handle.db.select().from(siteComponents).where(eq(siteComponents.scanId, scan.id));
    expect(php.map((c) => c.softwareType)).toContain('web_server');
  });

  it('only processes a scan once', async () => {
    const { scan } = await queuedScan();
    expect(await processScan(scan.id, deps())).toBe('completed');
    const before = fetcher.requested.length;
    expect(await processScan(scan.id, deps())).toBe('skipped');
    expect(fetcher.requested.length).toBe(before);
  });
});

describe('failStuckScans', () => {
  it('fails scans abandoned by a crashed worker', async () => {
    const { scan: running } = await queuedScan();
    await handle.db.update(scans).set({ status: 'running', startedAt: new Date(Date.now() - 60 * 60_000) }).where(eq(scans.id, running.id));
    const { scan: fresh } = await queuedScan();

    expect(await failStuckScans(handle.db, { runningMinutes: 10, queuedMinutes: 60 })).toBe(1);
    const [stuck] = await handle.db.select().from(scans).where(eq(scans.id, running.id));
    const [ok] = await handle.db.select().from(scans).where(eq(scans.id, fresh.id));
    expect(stuck!.status).toBe('failed');
    expect(ok!.status).toBe('queued');
  });
});
