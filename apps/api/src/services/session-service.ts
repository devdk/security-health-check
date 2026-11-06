import { and, eq, gt } from 'drizzle-orm';
import { sessions, type Database } from '@shc/db';
import { looksLikeToken, randomToken, sha256Hex } from '../lib/crypto';

export interface ResolvedSession {
  idHash: string;
  userId: string;
  expiresAt: Date;
  /** True when the expiry was pushed forward and the cookie should be re-sent. */
  extended: boolean;
}

/** Sliding expiry is only written at most this often, to avoid a DB write per request. */
const TOUCH_INTERVAL_MS = 60 * 60 * 1000;

export class SessionService {
  private readonly ttlMs: number;

  constructor(
    private readonly db: Database,
    ttlHours: number,
  ) {
    this.ttlMs = ttlHours * 60 * 60 * 1000;
  }

  get ttlSeconds(): number {
    return Math.floor(this.ttlMs / 1000);
  }

  async create(userId: string, ctx: { ip?: string; userAgent?: string }): Promise<{ token: string; expiresAt: Date }> {
    const token = randomToken();
    const expiresAt = new Date(Date.now() + this.ttlMs);
    await this.db.insert(sessions).values({
      idHash: sha256Hex(token),
      userId,
      expiresAt,
      ip: ctx.ip ?? null,
      userAgent: ctx.userAgent?.slice(0, 512) ?? null,
    });
    return { token, expiresAt };
  }

  async resolve(token: unknown): Promise<ResolvedSession | null> {
    if (!looksLikeToken(token)) return null;
    const idHash = sha256Hex(token);
    const [row] = await this.db
      .select({ idHash: sessions.idHash, userId: sessions.userId, expiresAt: sessions.expiresAt, lastSeenAt: sessions.lastSeenAt })
      .from(sessions)
      .where(and(eq(sessions.idHash, idHash), gt(sessions.expiresAt, new Date())))
      .limit(1);
    if (!row) return null;

    const now = Date.now();
    if (now - row.lastSeenAt.getTime() < TOUCH_INTERVAL_MS) {
      return { idHash: row.idHash, userId: row.userId, expiresAt: row.expiresAt, extended: false };
    }
    const expiresAt = new Date(now + this.ttlMs);
    await this.db.update(sessions).set({ lastSeenAt: new Date(now), expiresAt }).where(eq(sessions.idHash, idHash));
    return { idHash: row.idHash, userId: row.userId, expiresAt, extended: true };
  }

  async destroy(idHash: string): Promise<void> {
    await this.db.delete(sessions).where(eq(sessions.idHash, idHash));
  }

  async destroyAllForUser(userId: string): Promise<void> {
    await this.db.delete(sessions).where(eq(sessions.userId, userId));
  }
}
