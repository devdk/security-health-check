import { and, asc, eq, sql } from 'drizzle-orm';
import { softwareReleases, vulnCache, type Database } from '@shc/db';
import { compareVersions, type CoreStatus, type ReleaseLookup, type VulnLookup, type VulnRecord } from '@shc/scanner';
import type { SoftwareType } from '@shc/shared';
import type { FetchJson } from './http';
import { fetchDirectoryVersion } from './wporg';

/** Reads the local vulnerability cache. Wordfence first, so it wins when sources overlap. */
export class DbVulnLookup implements VulnLookup {
  constructor(private readonly db: Database) {}

  async forComponent(type: SoftwareType, slug: string): Promise<VulnRecord[]> {
    const rows = await this.db
      .select()
      .from(vulnCache)
      .where(and(eq(vulnCache.softwareType, type), eq(vulnCache.slug, slug)))
      .orderBy(sql`case ${vulnCache.source} when 'wordfence' then 0 when 'nvd' then 1 else 2 end`, asc(vulnCache.id));
    return rows.map((r) => ({
      source: r.source,
      sourceId: r.sourceId,
      title: r.title,
      cveIds: r.cveIds,
      cvssScore: r.cvssScore === null ? null : Number(r.cvssScore),
      severity: r.severity,
      affected: r.affected,
      fixedIn: r.fixedIn,
      references: r.references,
      informational: r.informational,
      recordUrl: r.recordUrl,
      copyrights: r.copyrights,
    }));
  }
}

const DAY_MS = 86_400_000;

/**
 * Latest-release data for scans. Core comes from the daily refresh. Plugins and themes
 * are looked up in the WordPress.org directory on first sight and cached for a day; a
 * failed lookup never fails the scan, it just means no "outdated" finding.
 */
export class DbReleaseLookup implements ReleaseLookup {
  constructor(
    private readonly db: Database,
    private readonly options: { fetchJson?: FetchJson; maxAgeMs?: number } = {},
  ) {}

  async coreStatus(version: string): Promise<{ status: CoreStatus; latest: string } | null> {
    const [row] = await this.db
      .select()
      .from(softwareReleases)
      .where(and(eq(softwareReleases.softwareType, 'core'), eq(softwareReleases.slug, 'wordpress')))
      .limit(1);
    if (!row?.latestVersion) return null;
    const versions = (row.details?.versions ?? {}) as Record<string, CoreStatus>;
    const known = versions[version] ?? versions[version.replace(/\.0$/, '')];
    if (known) return { status: known, latest: row.latestVersion };
    const cmp = compareVersions(version, row.latestVersion);
    if (cmp === 0) return { status: 'latest', latest: row.latestVersion };
    return cmp < 0 ? { status: 'outdated', latest: row.latestVersion } : null;
  }

  async latestVersion(type: 'plugin' | 'theme', slug: string): Promise<string | null> {
    const [cached] = await this.db
      .select()
      .from(softwareReleases)
      .where(and(eq(softwareReleases.softwareType, type), eq(softwareReleases.slug, slug)))
      .limit(1);
    if (cached && Date.now() - cached.fetchedAt.getTime() < (this.options.maxAgeMs ?? DAY_MS)) {
      return cached.found ? cached.latestVersion : null;
    }
    try {
      const { found, version } = await fetchDirectoryVersion(type, slug, this.options.fetchJson);
      await this.db
        .insert(softwareReleases)
        .values({ softwareType: type, slug, latestVersion: version, found, fetchedAt: new Date() })
        .onConflictDoUpdate({
          target: [softwareReleases.softwareType, softwareReleases.slug],
          set: { latestVersion: version, found, fetchedAt: sql`now()` },
        });
      return found ? version : null;
    } catch {
      return cached?.found ? cached.latestVersion : null;
    }
  }
}
