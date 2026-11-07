import { and, asc, eq, sql } from 'drizzle-orm';
import { vulnCache, type Database } from '@shc/db';
import type { VulnLookup, VulnRecord } from '@shc/scanner';
import type { SoftwareType } from '@shc/shared';

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
    }));
  }
}
