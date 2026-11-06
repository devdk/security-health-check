import { and, eq, gt, isNull, sql } from 'drizzle-orm';
import type { UserTokenPurpose } from '@shc/shared';
import { userTokens, type Database } from '@shc/db';
import { looksLikeToken, randomToken, sha256Hex } from '../lib/crypto';

export const TOKEN_TTL_MS: Record<UserTokenPurpose, number> = {
  email_verify: 24 * 60 * 60 * 1000,
  password_reset: 30 * 60 * 1000,
};

/** Single-use, hashed, expiring tokens for email links. */
export class UserTokenService {
  constructor(private readonly db: Database) {}

  /** Issues a new token and retires any earlier unused token for the same purpose. */
  async issue(userId: string, purpose: UserTokenPurpose): Promise<string> {
    const token = randomToken();
    await this.db.transaction(async (tx) => {
      await tx
        .update(userTokens)
        .set({ usedAt: sql`now()` })
        .where(and(eq(userTokens.userId, userId), eq(userTokens.purpose, purpose), isNull(userTokens.usedAt)));
      await tx.insert(userTokens).values({
        userId,
        purpose,
        tokenHash: sha256Hex(token),
        expiresAt: new Date(Date.now() + TOKEN_TTL_MS[purpose]),
      });
    });
    return token;
  }

  /** Atomically marks the token used. Returns the user id, or null if invalid, expired or already used. */
  async consume(token: unknown, purpose: UserTokenPurpose): Promise<string | null> {
    if (!looksLikeToken(token)) return null;
    const [row] = await this.db
      .update(userTokens)
      .set({ usedAt: sql`now()` })
      .where(
        and(
          eq(userTokens.tokenHash, sha256Hex(token)),
          eq(userTokens.purpose, purpose),
          isNull(userTokens.usedAt),
          gt(userTokens.expiresAt, new Date()),
        ),
      )
      .returning({ userId: userTokens.userId });
    return row?.userId ?? null;
  }
}
