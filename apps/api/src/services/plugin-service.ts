import { randomUUID } from 'node:crypto';
import { and, desc, eq, gt, isNull } from 'drizzle-orm';
import type { Redis } from 'ioredis';
import {
  deriveSiteKey,
  generatePairingCode,
  hashPairingCode,
  hashSiteKey,
  isFresh,
  normalizePairingCode,
  parseInsideReport,
  readSignedHeaders,
  REPORTS_PATH,
  sha256Hex,
  verifySignature,
} from '@shc/companion';
import type { Config } from '@shc/config';
import { audit, ensureFreshVerification, isUniqueViolation, markScanFailed, planFor, type ScanQueue } from '@shc/core';
import { pluginKeys, pluginPairingCodes, pluginReports, scans, sites, type Database } from '@shc/db';
import type { OwnershipChecker } from '@shc/net';
import { mask } from '@shc/shared';
import { safeEqual } from '../lib/crypto';
import { HttpError } from '../lib/errors';
import type { RequestContext } from './auth-service';
import { upgradeRequired } from './report-service';

export interface PluginStatusDto {
  /** False when PLUGIN_KEY_SECRET is unset: pairing is switched off on this server. */
  available: boolean;
  status: 'not_connected' | 'connected' | 'expired';
  connectedAt: string | null;
  expiresAt: string | null;
  lastReportAt: string | null;
  lastScanId: string | null;
  pluginVersion: string | null;
}

export interface PairingCodeDto {
  code: string;
  expiresAt: string;
  serviceUrl: string;
}

export interface PairResult {
  keyId: string;
  key: string;
  expiresAt: string;
}

export interface ReportReceipt {
  reportId: string;
  scanId: string;
}

export type RequestHeaders = Record<string, string | string[] | undefined>;

const DAY_MS = 86_400_000;
const HOUR_MS = 3_600_000;
const iso = (d: Date | null | undefined) => (d ? d.toISOString() : null);

const pluginUnavailable = () => new HttpError(503, 'plugin_unavailable', 'The companion plugin is not available on this server.');
const invalidCode = () => new HttpError(400, 'invalid_code', 'This pairing code is not valid. Create a new one on the site page and try again.');
const siteMismatch = () => new HttpError(400, 'site_mismatch', 'This WordPress site is not the site the plugin was connected for.');
const invalidSignature = () => new HttpError(401, 'invalid_signature', 'The request signature is missing or does not match.');
const invalidKey = () => new HttpError(401, 'invalid_key', 'This site key is not valid. Pair the plugin again with a new code from the site page.');
const invalidReport = (details: string[]) => new HttpError(400, 'invalid_report', 'The report was not accepted.', details);

/** The plugin's home URL must point at the verified domain or its www. twin. */
function isSiteHost(url: string, domain: string): boolean {
  let host: string;
  try {
    host = new URL(url).hostname.toLowerCase().replace(/\.$/, '');
  } catch {
    return false;
  }
  return host === domain || host === `www.${domain}` || `www.${host}` === domain;
}

/**
 * The companion plugin's side of the API. Owners create a one-time code in the dashboard;
 * the plugin trades it for a site key and then sends signed reports, each of which
 * becomes a queued inside scan. Only hashes of codes and keys are stored.
 */
export class PluginService {
  constructor(
    private readonly deps: {
      db: Database;
      ownership: OwnershipChecker;
      redis: Redis;
      queue: ScanQueue;
      plugin: Config['plugin'];
      /** Shown with the pairing code: the address the site admin enters in the plugin. */
      serviceUrl: string;
    },
  ) {}

  private requireSecret(): string {
    if (!this.deps.plugin.keySecret) throw pluginUnavailable();
    return this.deps.plugin.keySecret;
  }

  private async ownedSite(ownerId: string, siteId: string) {
    const [site] = await this.deps.db
      .select({ id: sites.id })
      .from(sites)
      .where(and(eq(sites.id, siteId), eq(sites.ownerId, ownerId)))
      .limit(1);
    if (!site) throw new HttpError(404, 'not_found', 'Site not found');
    return site;
  }

  /** The inside audit needs Pro and a site whose ownership is (freshly) verified. */
  private async assertMayConnect(ownerId: string, siteId: string): Promise<void> {
    if ((await planFor(this.deps.db, ownerId)) !== 'pro') throw upgradeRequired('The inside audit');
    const fresh = await ensureFreshVerification(this.deps.db, this.deps.ownership, siteId);
    if (!fresh.ok) throw new HttpError(403, 'not_verified', fresh.reason);
  }

  private async statusOf(siteId: string): Promise<PluginStatusDto> {
    const { db } = this.deps;
    const [key] = await db
      .select({ createdAt: pluginKeys.createdAt, expiresAt: pluginKeys.expiresAt })
      .from(pluginKeys)
      .where(and(eq(pluginKeys.siteId, siteId), isNull(pluginKeys.revokedAt)))
      .orderBy(desc(pluginKeys.createdAt))
      .limit(1);
    const [report] = await db
      .select({ receivedAt: pluginReports.receivedAt, scanId: pluginReports.scanId, pluginVersion: pluginReports.pluginVersion })
      .from(pluginReports)
      .where(eq(pluginReports.siteId, siteId))
      .orderBy(desc(pluginReports.receivedAt))
      .limit(1);
    return {
      available: this.deps.plugin.keySecret !== null,
      status: !key ? 'not_connected' : key.expiresAt.getTime() <= Date.now() ? 'expired' : 'connected',
      connectedAt: iso(key?.createdAt),
      expiresAt: iso(key?.expiresAt),
      lastReportAt: iso(report?.receivedAt),
      lastScanId: report?.scanId ?? null,
      pluginVersion: report?.pluginVersion ?? null,
    };
  }

  async status(ownerId: string, siteId: string): Promise<PluginStatusDto> {
    await this.ownedSite(ownerId, siteId);
    return this.statusOf(siteId);
  }

  /** A new one-time code, shown once. Any unused code of the site stops working. */
  async createPairingCode(ownerId: string, siteId: string, ctx: RequestContext): Promise<PairingCodeDto> {
    const { db, plugin } = this.deps;
    await this.ownedSite(ownerId, siteId);
    this.requireSecret();
    await this.assertMayConnect(ownerId, siteId);

    const code = generatePairingCode();
    const expiresAt = new Date(Date.now() + plugin.pairingCodeMinutes * 60_000);
    await db.transaction(async (tx) => {
      await tx.delete(pluginPairingCodes).where(and(eq(pluginPairingCodes.siteId, siteId), isNull(pluginPairingCodes.usedAt)));
      await tx.insert(pluginPairingCodes).values({ siteId, createdBy: ownerId, codeHash: hashPairingCode(normalizePairingCode(code)!), expiresAt });
    });
    await audit(db, { event: 'plugin_code_created', userId: ownerId, siteId, ip: ctx.ip, meta: { expiresAt: expiresAt.toISOString() } });
    return { code, expiresAt: expiresAt.toISOString(), serviceUrl: this.deps.serviceUrl };
  }

  /** Revokes every key of the site and withdraws unused codes, so the plugin can't report again until re-paired. */
  async disconnect(ownerId: string, siteId: string, ctx: RequestContext): Promise<PluginStatusDto> {
    const { db } = this.deps;
    await this.ownedSite(ownerId, siteId);
    const revoked = await db.transaction(async (tx) => {
      await tx.delete(pluginPairingCodes).where(and(eq(pluginPairingCodes.siteId, siteId), isNull(pluginPairingCodes.usedAt)));
      return tx
        .update(pluginKeys)
        .set({ revokedAt: new Date() })
        .where(and(eq(pluginKeys.siteId, siteId), isNull(pluginKeys.revokedAt)))
        .returning({ id: pluginKeys.id });
    });
    await audit(db, { event: 'plugin_disconnected', userId: ownerId, siteId, ip: ctx.ip, meta: { revokedKeys: revoked.length } });
    return this.statusOf(siteId);
  }

  /**
   * Called by the plugin with the code the admin typed. Checks run in the documented
   * order. On success the site's previous keys are revoked and a new key is issued;
   * the key is returned this once and never stored.
   */
  async pair(input: { code: string; homeUrl: string; pluginVersion: string }, ctx: RequestContext): Promise<PairResult> {
    const { db, plugin } = this.deps;
    const secret = this.requireSecret();

    const normalized = normalizePairingCode(input.code);
    if (!normalized) throw invalidCode();
    const [row] = await db
      .select({ code: pluginPairingCodes, domain: sites.domain, ownerId: sites.ownerId })
      .from(pluginPairingCodes)
      .innerJoin(sites, eq(sites.id, pluginPairingCodes.siteId))
      .where(and(eq(pluginPairingCodes.codeHash, hashPairingCode(normalized)), isNull(pluginPairingCodes.usedAt), gt(pluginPairingCodes.expiresAt, new Date())))
      .limit(1);
    if (!row) throw invalidCode();
    const siteId = row.code.siteId;

    if (!isSiteHost(input.homeUrl, row.domain)) throw siteMismatch();
    await this.assertMayConnect(row.ownerId, siteId);

    const keyId = randomUUID();
    const key = deriveSiteKey(secret, keyId);
    const now = new Date();
    const expiresAt = new Date(now.getTime() + plugin.keyTtlDays * DAY_MS);
    await db.transaction(async (tx) => {
      const [used] = await tx
        .update(pluginPairingCodes)
        .set({ usedAt: now })
        .where(and(eq(pluginPairingCodes.id, row.code.id), isNull(pluginPairingCodes.usedAt)))
        .returning({ id: pluginPairingCodes.id });
      if (!used) throw invalidCode();
      await tx.update(pluginKeys).set({ revokedAt: now }).where(and(eq(pluginKeys.siteId, siteId), isNull(pluginKeys.revokedAt)));
      await tx.insert(pluginKeys).values({ id: keyId, siteId, keyHash: hashSiteKey(key), expiresAt });
    });
    await audit(db, { event: 'plugin_paired', userId: row.ownerId, siteId, ip: ctx.ip, meta: { keyId, pluginVersion: input.pluginVersion } });
    return { keyId, key, expiresAt: expiresAt.toISOString() };
  }

  /** Fixed hourly window per site (so re-pairing doesn't reset it), shared by every API process through Valkey. */
  private async withinHourlyLimit(siteId: string): Promise<boolean> {
    const counter = `shc:plugin-reports:${siteId}:${Math.floor(Date.now() / HOUR_MS)}`;
    const results = await this.deps.redis.multi().incr(counter).expire(counter, HOUR_MS / 1000).exec();
    const count = Number(results?.[0]?.[1] ?? Number.POSITIVE_INFINITY);
    return count <= this.deps.plugin.reportsPerHour;
  }

  /**
   * A signed report from the plugin. The checks run in the documented order and stop at
   * the first failure; the rate limit counts only requests whose signature verified.
   */
  async receiveReport(headers: RequestHeaders, body: Buffer, ctx: RequestContext): Promise<ReportReceipt> {
    const { db, queue } = this.deps;
    const secret = this.requireSecret();

    const signed = readSignedHeaders(headers);
    if (!signed) throw invalidSignature();
    if (!isFresh(signed.timestamp)) throw new HttpError(401, 'stale_request', "The request's timestamp is too far from the server clock. Check the site's clock.");

    const [row] = await db
      .select({ key: pluginKeys, domain: sites.domain, ownerId: sites.ownerId })
      .from(pluginKeys)
      .innerJoin(sites, eq(sites.id, pluginKeys.siteId))
      .where(eq(pluginKeys.id, signed.keyId))
      .limit(1);
    if (!row || row.key.revokedAt) throw invalidKey();
    if (row.key.expiresAt.getTime() <= Date.now()) throw new HttpError(401, 'key_expired', 'This site key has expired. Pair the plugin again with a new code from the site page.');
    const key = deriveSiteKey(secret, signed.keyId);
    if (!safeEqual(hashSiteKey(key), row.key.keyHash)) throw invalidKey();
    if (!verifySignature(key, { method: 'POST', path: REPORTS_PATH, timestamp: signed.timestamp, nonce: signed.nonce, body }, signed.signature)) {
      throw invalidSignature();
    }

    if (!(await this.withinHourlyLimit(row.key.siteId))) throw new HttpError(429, 'rate_limited', 'This site has sent too many reports. Try again later.');
    // Ownership is re-checked like before a scan: a domain sold with its WordPress install
    // must stop reporting to the previous owner's account.
    await this.assertMayConnect(row.ownerId, row.key.siteId);

    let payload: unknown;
    try {
      payload = JSON.parse(body.toString('utf8'));
    } catch {
      throw invalidReport(['/ body is not valid JSON']);
    }
    const parsed = parseInsideReport(payload);
    if (!parsed.ok) throw invalidReport(parsed.errors);
    if (!isSiteHost(parsed.report.site.homeUrl, row.domain)) throw siteMismatch();
    const report = { ...parsed.report, admins: parsed.report.admins.map((a) => ({ ...a, login: mask(a.login) })) };

    const siteId = row.key.siteId;
    let receipt: ReportReceipt;
    try {
      receipt = await db.transaction(async (tx) => {
        const [scan] = await tx.insert(scans).values({ siteId, requestedBy: row.ownerId, kind: 'inside', trigger: 'plugin', status: 'queued' }).returning({ id: scans.id });
        const [stored] = await tx
          .insert(pluginReports)
          .values({
            siteId,
            pluginKeyId: signed.keyId,
            scanId: scan!.id,
            signedAt: new Date(signed.timestamp * 1000),
            nonce: signed.nonce,
            pluginVersion: report.plugin.version,
            payload: report,
            payloadSha256: sha256Hex(body),
          })
          .returning({ id: pluginReports.id });
        await tx.update(pluginKeys).set({ lastUsedAt: new Date() }).where(eq(pluginKeys.id, signed.keyId));
        return { reportId: stored!.id, scanId: scan!.id };
      });
    } catch (err) {
      if (isUniqueViolation(err)) throw new HttpError(409, 'replayed', 'This report was already received.');
      throw err;
    }

    try {
      await queue.enqueue(receipt.scanId);
    } catch {
      await markScanFailed(db, receipt.scanId, 'The report could not be queued for analysis.');
      throw new HttpError(503, 'queue_unavailable', 'Reports cannot be processed right now. Please try again shortly.');
    }
    await audit(db, {
      event: 'plugin_report_received',
      userId: row.ownerId,
      siteId,
      ip: ctx.ip,
      meta: { ...receipt, keyId: signed.keyId, pluginVersion: report.plugin.version },
    });
    return receipt;
  }
}
