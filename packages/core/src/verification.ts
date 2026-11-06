import { randomBytes } from 'node:crypto';
import { eq, sql } from 'drizzle-orm';
import { sites, type Database } from '@shc/db';
import type { OwnershipChecker, OwnershipResult } from '@shc/net';
import { siteStatus, type VerifyMethod } from '@shc/shared';
import { audit } from './audit';

type SiteRow = typeof sites.$inferSelect;

/** 128-bit random token, hex so it is safe in DNS records and file names. */
export function newVerificationToken(): string {
  return randomBytes(16).toString('hex');
}

/**
 * Runs an ownership check and records the outcome on the site. A failed check never
 * clears an earlier success; freshness is judged from verified_at.
 */
export async function runVerification(
  db: Database,
  checker: OwnershipChecker,
  site: SiteRow,
  method: VerifyMethod,
  actor: { userId?: string | null; ip?: string | null; reverify?: boolean } = {},
): Promise<{ result: OwnershipResult; site: SiteRow }> {
  const result = await checker.check(method, site.domain, site.verificationToken);
  const now = new Date();

  const [updated] = await db
    .update(sites)
    .set(
      result.ok
        ? { verifiedAt: now, verificationMethod: method, lastVerifyAttemptAt: now, lastVerifyError: null }
        : { lastVerifyAttemptAt: now, lastVerifyError: result.reason.slice(0, 500) },
    )
    .where(eq(sites.id, site.id))
    .returning();

  const event = actor.reverify
    ? result.ok
      ? 'site_reverified'
      : 'site_reverify_failed'
    : result.ok
      ? 'site_verified'
      : 'site_verify_failed';
  await audit(db, { event, userId: actor.userId, siteId: site.id, ip: actor.ip, meta: { method, domain: site.domain } });

  return { result, site: updated ?? site };
}

export type FreshnessResult = { ok: true; site: SiteRow; rechecked: boolean } | { ok: false; reason: string; site?: SiteRow };

/**
 * Rule 1 of the product: never scan a site whose ownership isn't verified, and re-verify
 * when the last successful check is older than VERIFICATION_TTL_HOURS. Call this
 * immediately before every scan, from the API and again from the worker.
 */
export async function ensureFreshVerification(db: Database, checker: OwnershipChecker, siteId: string): Promise<FreshnessResult> {
  const [site] = await db.select().from(sites).where(eq(sites.id, siteId)).limit(1);
  if (!site) return { ok: false, reason: 'Site not found' };

  const status = siteStatus(site.verifiedAt);
  if (status === 'verified') return { ok: true, site, rechecked: false };
  if (status === 'unverified' || !site.verificationMethod) {
    return { ok: false, reason: 'Prove you own this site before scanning it.', site };
  }

  const { result, site: updated } = await runVerification(db, checker, site, site.verificationMethod, { reverify: true });
  if (result.ok) return { ok: true, site: updated, rechecked: true };
  return {
    ok: false,
    reason: `We re-checked ownership before scanning and it failed: ${result.reason}`,
    site: updated,
  };
}

/** Number of sites a user already has. */
export async function countSites(db: Database, ownerId: string): Promise<number> {
  const [row] = await db.select({ n: sql<number>`count(*)::int` }).from(sites).where(eq(sites.ownerId, ownerId));
  return row?.n ?? 0;
}
