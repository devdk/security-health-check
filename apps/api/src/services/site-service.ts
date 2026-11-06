import { and, asc, eq } from 'drizzle-orm';
import { audit, countSites, newVerificationToken, runVerification } from '@shc/core';
import { sites, subscriptions, type Database } from '@shc/db';
import { ownershipInstructions, type OwnershipChecker, type OwnershipInstructions } from '@shc/net';
import { effectivePlan, normaliseDomain, siteStatus, SITE_LIMITS, type SiteStatus, type VerifyMethod } from '@shc/shared';
import { HttpError } from '../lib/errors';
import type { RequestContext } from './auth-service';

type SiteRow = typeof sites.$inferSelect;

export interface SiteDto {
  id: string;
  domain: string;
  status: SiteStatus;
  verificationMethod: VerifyMethod | null;
  verifiedAt: string | null;
  lastVerifyAttemptAt: string | null;
  lastVerifyError: string | null;
  createdAt: string;
  instructions: OwnershipInstructions;
}

const iso = (d: Date | null) => (d ? d.toISOString() : null);

export function toSiteDto(row: SiteRow): SiteDto {
  return {
    id: row.id,
    domain: row.domain,
    status: siteStatus(row.verifiedAt),
    verificationMethod: row.verificationMethod,
    verifiedAt: iso(row.verifiedAt),
    lastVerifyAttemptAt: iso(row.lastVerifyAttemptAt),
    lastVerifyError: row.lastVerifyError,
    createdAt: row.createdAt.toISOString(),
    instructions: ownershipInstructions(row.domain, row.verificationToken),
  };
}

const notFound = () => new HttpError(404, 'not_found', 'Site not found');

/**
 * Every query is scoped to the signed-in owner. Another user's site id behaves exactly
 * like a missing one (404), so ids can't be probed.
 */
export class SiteService {
  constructor(
    private readonly deps: {
      db: Database;
      ownership: OwnershipChecker;
      /** Dev-only hostnames that bypass the public-domain rules (local test WordPress). */
      allowHosts: readonly string[];
    },
  ) {}

  async list(ownerId: string): Promise<SiteDto[]> {
    const rows = await this.deps.db.select().from(sites).where(eq(sites.ownerId, ownerId)).orderBy(asc(sites.createdAt));
    return rows.map(toSiteDto);
  }

  private async row(ownerId: string, siteId: string): Promise<SiteRow> {
    const [row] = await this.deps.db
      .select()
      .from(sites)
      .where(and(eq(sites.id, siteId), eq(sites.ownerId, ownerId)))
      .limit(1);
    if (!row) throw notFound();
    return row;
  }

  async get(ownerId: string, siteId: string): Promise<SiteDto> {
    return toSiteDto(await this.row(ownerId, siteId));
  }

  async create(ownerId: string, rawDomain: string, ctx: RequestContext): Promise<SiteDto> {
    const { db } = this.deps;
    const parsed = normaliseDomain(rawDomain, { allow: this.deps.allowHosts });
    if (!parsed.ok) throw new HttpError(400, 'invalid_domain', parsed.reason);

    const [sub] = await db
      .select({ plan: subscriptions.plan, status: subscriptions.status })
      .from(subscriptions)
      .where(eq(subscriptions.userId, ownerId))
      .limit(1);
    const plan = effectivePlan(sub?.plan, sub?.status);
    const limit = SITE_LIMITS[plan];
    if ((await countSites(db, ownerId)) >= limit) {
      throw new HttpError(403, 'site_limit_reached', `Your ${plan} plan allows up to ${limit} sites. Remove one or upgrade to add more.`);
    }

    const [row] = await db
      .insert(sites)
      .values({ ownerId, domain: parsed.domain, verificationToken: newVerificationToken() })
      .onConflictDoNothing({ target: [sites.ownerId, sites.domain] })
      .returning();
    if (!row) throw new HttpError(409, 'site_exists', `You've already added ${parsed.domain}.`);

    await audit(db, { event: 'site_added', userId: ownerId, siteId: row.id, ip: ctx.ip, meta: { domain: row.domain } });
    return toSiteDto(row);
  }

  async verify(ownerId: string, siteId: string, method: VerifyMethod, ctx: RequestContext) {
    const site = await this.row(ownerId, siteId);
    const { result, site: updated } = await runVerification(this.deps.db, this.deps.ownership, site, method, {
      userId: ownerId,
      ip: ctx.ip,
    });
    return {
      verified: result.ok,
      message: result.ok ? `Ownership confirmed. ${result.detail}.` : result.reason,
      site: toSiteDto(updated),
    };
  }

  async remove(ownerId: string, siteId: string, ctx: RequestContext): Promise<void> {
    const { db } = this.deps;
    const [deleted] = await db
      .delete(sites)
      .where(and(eq(sites.id, siteId), eq(sites.ownerId, ownerId)))
      .returning({ id: sites.id, domain: sites.domain });
    if (!deleted) throw notFound();
    // siteId is left out: the row is gone and the audit FK would null it anyway.
    await audit(db, { event: 'site_deleted', userId: ownerId, ip: ctx.ip, meta: { siteId: deleted.id, domain: deleted.domain } });
  }
}
