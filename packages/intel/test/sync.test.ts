import { eq, sql } from 'drizzle-orm';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { createDb, softwareReleases, vulnCache, vulnSyncRuns, type DbHandle } from '@shc/db';
import type { FetchJson } from '../src/http';
import { DbReleaseLookup, DbVulnLookup } from '../src/lookups';
import { refreshCoreReleases, syncVulnSource } from '../src/sync';
import type { NormalizedVuln, VulnSourceAdapter } from '../src/types';
import { intelTestDbUrl } from './global-setup';

let handle: DbHandle;

function vuln(over: Partial<NormalizedVuln> = {}): NormalizedVuln {
  return {
    source: 'wordfence',
    sourceId: '00000000-0000-0000-0000-000000000001',
    softwareType: 'plugin',
    slug: 'contact-form-7',
    title: 'Unrestricted File Upload',
    cveIds: ['CVE-2020-35489'],
    cvssScore: 9.8,
    severity: 'critical',
    affected: [{ to: '5.3.1', toInclusive: true }],
    fixedIn: '5.3.2',
    references: [],
    informational: false,
    description: null,
    remediation: 'Update to 5.3.2',
    cwe: null,
    recordUrl: 'https://www.wordfence.com/threat-intel/vulnerabilities/id/00000000-0000-0000-0000-000000000001',
    copyrights: { holders: { defiant: { notice: 'Copyright Defiant Inc.', license: 'licence text', licenseUrl: 'https://example.org/l' } } },
    publishedAt: null,
    updatedAt: null,
    ...over,
  };
}

function adapter(rows: () => NormalizedVuln[] | Promise<NormalizedVuln[]>, mode: 'full' | 'incremental' = 'full', source: 'wordfence' | 'nvd' = 'wordfence') {
  const seen: Array<Date | undefined> = [];
  const a: VulnSourceAdapter = {
    source,
    mode,
    disabledReason: () => null,
    fetch: async ({ since } = {}) => {
      seen.push(since);
      return rows();
    },
  };
  return { adapter: a, seen };
}

beforeAll(() => {
  handle = createDb(intelTestDbUrl(), { max: 3 });
});
afterAll(async () => {
  await handle.close();
});
beforeEach(async () => {
  await handle.db.execute(sql`truncate table vuln_cache, vuln_sync_runs, software_releases restart identity`);
});

const count = async () => (await handle.db.select().from(vulnCache)).length;

describe('syncVulnSource', () => {
  it('stores rows with attribution and records the run', async () => {
    const result = await syncVulnSource(handle.db, adapter(() => [vuln(), vuln({ slug: 'other', sourceId: '00000000-0000-0000-0000-000000000002' })]).adapter);
    expect(result).toMatchObject({ status: 'ok', rows: 2 });
    const [row] = await handle.db.select().from(vulnCache).where(eq(vulnCache.slug, 'contact-form-7'));
    expect(row).toMatchObject({ cvssScore: '9.8', fixedIn: '5.3.2', remediation: 'Update to 5.3.2' });
    expect(row!.copyrights?.holders.defiant?.notice).toBe('Copyright Defiant Inc.');
    const [run] = await handle.db.select().from(vulnSyncRuns);
    expect(run).toMatchObject({ source: 'wordfence', status: 'ok', recordsUpserted: 2 });
  });

  it('updates changed records in place and removes ones that left a full feed', async () => {
    let rows = Array.from({ length: 4 }, (_, i) => vuln({ slug: `p${i}`, sourceId: `00000000-0000-0000-0000-00000000000${i}` }));
    const { adapter: a } = adapter(() => rows);
    await syncVulnSource(handle.db, a);
    rows = [vuln({ slug: 'p0', sourceId: '00000000-0000-0000-0000-000000000000', title: 'Renamed' }), ...rows.slice(1, 3)];
    const result = await syncVulnSource(handle.db, a);
    expect(result).toMatchObject({ status: 'ok', rows: 3, removed: 1 });
    expect(await count()).toBe(3);
    const [p0] = await handle.db.select().from(vulnCache).where(eq(vulnCache.slug, 'p0'));
    expect(p0!.title).toBe('Renamed');
  });

  it('keeps the cache when a full feed comes back suspiciously small', async () => {
    const many = Array.from({ length: 10 }, (_, i) => vuln({ slug: `p${i}`, sourceId: `00000000-0000-0000-0000-0000000000${String(i).padStart(2, '0')}` }));
    let rows = many;
    const { adapter: a } = adapter(() => rows);
    await syncVulnSource(handle.db, a);
    rows = many.slice(0, 2);
    const result = await syncVulnSource(handle.db, a);
    expect(result.removed).toBe(0);
    expect(result.note).toMatch(/kept old rows/);
    expect(await count()).toBe(10);
  });

  it('collapses duplicate rows from one feed instead of failing', async () => {
    const result = await syncVulnSource(handle.db, adapter(() => [vuln(), vuln({ title: 'dupe' })]).adapter);
    expect(result).toMatchObject({ status: 'ok', rows: 1 });
  });

  it('records failures without touching existing data', async () => {
    await syncVulnSource(handle.db, adapter(() => [vuln()]).adapter);
    const result = await syncVulnSource(
      handle.db,
      adapter(() => {
        throw new Error('Wordfence rate limit reached');
      }).adapter,
    );
    expect(result).toMatchObject({ status: 'failed', note: 'Wordfence rate limit reached' });
    expect(await count()).toBe(1);
    const runs = await handle.db.select().from(vulnSyncRuns).orderBy(vulnSyncRuns.id);
    expect(runs.map((r) => r.status)).toEqual(['ok', 'failed']);
  });

  it('asks incremental sources only for changes since the last good run', async () => {
    const { adapter: a, seen } = adapter(() => [vuln({ source: 'nvd', softwareType: 'php', slug: 'php', sourceId: 'CVE-2024-4577' })], 'incremental', 'nvd');
    await syncVulnSource(handle.db, a);
    await syncVulnSource(handle.db, a);
    expect(seen[0]).toBeUndefined();
    expect(seen[1]).toBeInstanceOf(Date);
  });

  it('skips disabled sources without recording a run', async () => {
    const disabled: VulnSourceAdapter = { source: 'osv', mode: 'incremental', disabledReason: () => 'off', fetch: async () => [] };
    expect(await syncVulnSource(handle.db, disabled)).toMatchObject({ status: 'skipped', note: 'off' });
    expect(await handle.db.select().from(vulnSyncRuns)).toEqual([]);
  });
});

describe('lookups', () => {
  it('returns cached vulnerabilities with attribution links, Wordfence first', async () => {
    await syncVulnSource(handle.db, adapter(() => [vuln({ source: 'nvd', sourceId: 'CVE-2020-35489', recordUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2020-35489' })], 'incremental', 'nvd').adapter);
    await syncVulnSource(handle.db, adapter(() => [vuln({ informational: true })]).adapter);
    const records = await new DbVulnLookup(handle.db).forComponent('plugin', 'contact-form-7');
    expect(records.map((r) => r.source)).toEqual(['wordfence', 'nvd']);
    expect(records[0]).toMatchObject({ cvssScore: 9.8, informational: true, recordUrl: expect.stringContaining('wordfence.com') });
  });

  it('answers core status from the daily WordPress.org data', async () => {
    const get: FetchJson = async () => ({ status: 200, json: { '6.4.2': 'insecure', '7.0.8': 'outdated', '7.1.4': 'latest' } });
    await refreshCoreReleases(handle.db, get);
    const lookup = new DbReleaseLookup(handle.db);
    expect(await lookup.coreStatus('6.4.2')).toEqual({ status: 'insecure', latest: '7.1.4' });
    expect(await lookup.coreStatus('7.1.4')).toEqual({ status: 'latest', latest: '7.1.4' });
    expect(await lookup.coreStatus('6.0.99')).toEqual({ status: 'outdated', latest: '7.1.4' }); // unknown but older
    expect(await lookup.coreStatus('99.0')).toBeNull();
  });

  it('looks plugins up once and serves repeats from the cache', async () => {
    let calls = 0;
    const get: FetchJson = async (url) => {
      calls++;
      return url.includes('premium') ? { status: 404, json: { error: 'Plugin not found.' } } : { status: 200, json: { version: '6.1.2' } };
    };
    const lookup = new DbReleaseLookup(handle.db, { fetchJson: get });
    expect(await lookup.latestVersion('plugin', 'contact-form-7')).toBe('6.1.2');
    expect(await lookup.latestVersion('plugin', 'contact-form-7')).toBe('6.1.2');
    expect(await lookup.latestVersion('plugin', 'premium-thing')).toBeNull();
    expect(await lookup.latestVersion('plugin', 'premium-thing')).toBeNull();
    expect(calls).toBe(2);
    const [row] = await handle.db.select().from(softwareReleases).where(eq(softwareReleases.slug, 'premium-thing'));
    expect(row!.found).toBe(false);
  });

  it('never fails a scan because WordPress.org is down', async () => {
    const get: FetchJson = async () => {
      throw new Error('ECONNRESET');
    };
    expect(await new DbReleaseLookup(handle.db, { fetchJson: get }).latestVersion('plugin', 'x')).toBeNull();
  });
});
