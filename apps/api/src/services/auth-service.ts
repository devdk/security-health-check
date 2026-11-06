import { eq, sql } from 'drizzle-orm';
import type { Config } from '@shc/config';
import { effectivePlan, type Plan } from '@shc/shared';
import { subscriptions, users, type Database } from '@shc/db';
import { audit } from '@shc/core';
import { normaliseEmail } from '../lib/email';
import { HttpError, invalidCredentials } from '../lib/errors';
import type { Mailer } from '../lib/mailer';
import { burnPasswordCheck, hashPassword, needsRehash, verifyPassword } from '../lib/passwords';
import type { SessionService } from './session-service';
import type { UserTokenService } from './user-token-service';

/** Failed logins before the account is temporarily locked. */
export const MAX_FAILED_LOGINS = 10;
export const LOCKOUT_MINUTES = 15;

export interface RequestContext {
  ip?: string;
  userAgent?: string;
}

export interface PublicUser {
  id: string;
  email: string;
  emailVerified: boolean;
  plan: Plan;
}

interface Deps {
  db: Database;
  config: Config;
  mailer: Mailer;
  sessions: SessionService;
  tokens: UserTokenService;
}

export class AuthService {
  constructor(private readonly deps: Deps) {}

  /**
   * Always resolves the same way whether or not the email is already registered, so the
   * endpoint cannot be used to discover accounts. Existing owners get a notice email instead.
   */
  async register(rawEmail: string, password: string, ctx: RequestContext): Promise<void> {
    const { db, mailer, tokens, config } = this.deps;
    const email = normaliseEmail(rawEmail);
    if (password.toLowerCase() === email) {
      throw new HttpError(400, 'weak_password', 'Password must not be your email address');
    }
    const passwordHash = await hashPassword(password);

    const created = await db.transaction(async (tx) => {
      const [user] = await tx
        .insert(users)
        .values({ email, passwordHash })
        .onConflictDoNothing({ target: users.email })
        .returning({ id: users.id });
      if (!user) return null;
      await tx.insert(subscriptions).values({ userId: user.id, plan: 'free', status: 'active' });
      return user;
    });

    if (created) {
      const token = await tokens.issue(created.id, 'email_verify');
      await mailer.send({
        to: email,
        subject: 'Confirm your email for Security Health Check',
        text: [
          'Welcome to Security Health Check.',
          '',
          'Confirm your email address by opening this link (valid for 24 hours):',
          `${config.web.baseUrl}/verify-email#token=${token}`,
          '',
          "If you didn't create an account, you can ignore this email.",
        ].join('\n'),
      });
      await audit(db, { event: 'register', userId: created.id, ip: ctx.ip });
      return;
    }

    const [existing] = await db.select({ id: users.id }).from(users).where(eq(users.email, email)).limit(1);
    await mailer.send({
      to: email,
      subject: 'Someone tried to register with your email',
      text: [
        'Someone tried to create a Security Health Check account with this email address, but you already have one.',
        '',
        `If this was you, sign in at ${config.web.baseUrl}/login or reset your password at ${config.web.baseUrl}/forgot-password.`,
        "If it wasn't you, no action is needed.",
      ].join('\n'),
    });
    await audit(db, { event: 'register_existing_email', userId: existing?.id, ip: ctx.ip });
  }

  async verifyEmail(token: string, ctx: RequestContext): Promise<boolean> {
    const userId = await this.deps.tokens.consume(token, 'email_verify');
    if (!userId) return false;
    await this.deps.db
      .update(users)
      .set({ emailVerifiedAt: sql`coalesce(${users.emailVerifiedAt}, now())`, updatedAt: sql`now()` })
      .where(eq(users.id, userId));
    await audit(this.deps.db, { event: 'email_verified', userId, ip: ctx.ip });
    return true;
  }

  async resendVerification(rawEmail: string): Promise<void> {
    const email = normaliseEmail(rawEmail);
    const [user] = await this.deps.db
      .select({ id: users.id, verified: users.emailVerifiedAt })
      .from(users)
      .where(eq(users.email, email))
      .limit(1);
    if (!user || user.verified) return;
    const token = await this.deps.tokens.issue(user.id, 'email_verify');
    await this.deps.mailer.send({
      to: email,
      subject: 'Confirm your email for Security Health Check',
      text: `Confirm your email address by opening this link (valid for 24 hours):\n${this.deps.config.web.baseUrl}/verify-email#token=${token}`,
    });
  }

  async login(rawEmail: string, password: string, ctx: RequestContext): Promise<{ user: PublicUser; token: string }> {
    const { db, sessions } = this.deps;
    const email = normaliseEmail(rawEmail);
    const [user] = await db.select().from(users).where(eq(users.email, email)).limit(1);

    if (!user) {
      await burnPasswordCheck(password);
      await audit(db, { event: 'login_failed', ip: ctx.ip, meta: { reason: 'unknown_email' } });
      throw invalidCredentials();
    }

    if (user.lockedUntil && user.lockedUntil.getTime() > Date.now()) {
      await burnPasswordCheck(password);
      await audit(db, { event: 'login_locked', userId: user.id, ip: ctx.ip });
      throw invalidCredentials();
    }

    if (!(await verifyPassword(user.passwordHash, password))) {
      await this.recordFailedLogin(user.id);
      await audit(db, { event: 'login_failed', userId: user.id, ip: ctx.ip, meta: { reason: 'bad_password' } });
      throw invalidCredentials();
    }

    if (!user.emailVerifiedAt) {
      throw new HttpError(403, 'email_not_verified', 'Confirm your email address before signing in');
    }

    const updates: Partial<typeof users.$inferInsert> = { failedLogins: 0, lockedUntil: null };
    if (needsRehash(user.passwordHash)) updates.passwordHash = await hashPassword(password);
    await db.update(users).set(updates).where(eq(users.id, user.id));

    const { token } = await sessions.create(user.id, ctx);
    await audit(db, { event: 'login', userId: user.id, ip: ctx.ip });
    return { user: await this.getPublicUser(user.id), token };
  }

  async logout(session: { userId: string; sessionIdHash: string }, ctx: RequestContext): Promise<void> {
    await this.deps.sessions.destroy(session.sessionIdHash);
    await audit(this.deps.db, { event: 'logout', userId: session.userId, ip: ctx.ip });
  }

  /**
   * Counts a failure atomically. An expired lock resets the counter, so a user is not
   * re-locked by a single typo after waiting out the lockout.
   */
  private async recordFailedLogin(userId: string): Promise<void> {
    const lockExpired = sql`(${users.lockedUntil} is not null and ${users.lockedUntil} <= now())`;
    const nextCount = sql`(case when ${lockExpired} then 1 else ${users.failedLogins} + 1 end)`;
    await this.deps.db
      .update(users)
      .set({
        failedLogins: nextCount,
        lockedUntil: sql`case
          when ${nextCount} >= ${MAX_FAILED_LOGINS} then now() + make_interval(mins => ${LOCKOUT_MINUTES})
          when ${lockExpired} then null
          else ${users.lockedUntil} end`,
      })
      .where(eq(users.id, userId));
  }

  async requestPasswordReset(rawEmail: string, ctx: RequestContext): Promise<void> {
    const { db, tokens, mailer, config } = this.deps;
    const email = normaliseEmail(rawEmail);
    const [user] = await db.select({ id: users.id }).from(users).where(eq(users.email, email)).limit(1);
    await audit(db, { event: 'password_reset_requested', userId: user?.id, ip: ctx.ip });
    if (!user) return;
    const token = await tokens.issue(user.id, 'password_reset');
    await mailer.send({
      to: email,
      subject: 'Reset your Security Health Check password',
      text: [
        'Someone asked to reset the password for your Security Health Check account.',
        '',
        'Open this link to choose a new password (valid for 30 minutes):',
        `${config.web.baseUrl}/reset-password#token=${token}`,
        '',
        "If you didn't ask for this, ignore this email. Your password won't change.",
      ].join('\n'),
    });
  }

  /** Sets a new password, clears any lockout and signs the user out everywhere. */
  async resetPassword(token: string, newPassword: string, ctx: RequestContext): Promise<boolean> {
    const { db, tokens, sessions } = this.deps;
    const userId = await tokens.consume(token, 'password_reset');
    if (!userId) return false;
    const passwordHash = await hashPassword(newPassword);
    await db
      .update(users)
      .set({
        passwordHash,
        failedLogins: 0,
        lockedUntil: null,
        // The reset link proves control of the inbox.
        emailVerifiedAt: sql`coalesce(${users.emailVerifiedAt}, now())`,
        updatedAt: sql`now()`,
      })
      .where(eq(users.id, userId));
    await sessions.destroyAllForUser(userId);
    await audit(db, { event: 'password_reset', userId, ip: ctx.ip });
    return true;
  }

  async getPublicUser(userId: string): Promise<PublicUser> {
    const [row] = await this.deps.db
      .select({ id: users.id, email: users.email, verifiedAt: users.emailVerifiedAt, plan: subscriptions.plan, status: subscriptions.status })
      .from(users)
      .leftJoin(subscriptions, eq(subscriptions.userId, users.id))
      .where(eq(users.id, userId))
      .limit(1);
    if (!row) throw new HttpError(401, 'unauthorised', 'Sign in required');
    return { id: row.id, email: row.email, emailVerified: row.verifiedAt !== null, plan: effectivePlan(row.plan, row.status) };
  }
}
