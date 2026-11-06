import { and, eq } from 'drizzle-orm';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { auditEvents, sessions, subscriptions, users, userTokens } from '@shc/db';
import { MAX_FAILED_LOGINS } from '../src/services/auth-service';
import { createTestContext, login, post, registerAndVerify, resetState, tokenFromMail, type TestContext } from './helpers';

const EMAIL = 'owner@example.com';
const PASSWORD = 'correct horse battery staple';

let ctx: TestContext;

beforeAll(async () => {
  ctx = await createTestContext();
});
afterAll(async () => {
  await ctx.close();
});
beforeEach(async () => {
  await resetState(ctx);
});

describe('registration and email verification', () => {
  it('creates a user on the free plan and emails a verification link', async () => {
    const res = await post(ctx, '/api/auth/register', { email: EMAIL, password: PASSWORD });
    expect(res.statusCode).toBe(202);

    const [user] = await ctx.db.select().from(users).where(eq(users.email, EMAIL));
    expect(user?.emailVerifiedAt).toBeNull();
    expect(user?.passwordHash.startsWith('$argon2id$')).toBe(true);

    const [sub] = await ctx.db.select().from(subscriptions).where(eq(subscriptions.userId, user!.id));
    expect(sub?.plan).toBe('free');

    const mail = ctx.mailer.lastTo(EMAIL);
    expect(mail?.text).toContain('http://localhost:5173/verify-email#token=');
  });

  it('blocks sign-in until the email is confirmed', async () => {
    await post(ctx, '/api/auth/register', { email: EMAIL, password: PASSWORD });
    const res = await post(ctx, '/api/auth/login', { email: EMAIL, password: PASSWORD });
    expect(res.statusCode).toBe(403);
    expect(res.json().error).toBe('email_not_verified');
    expect(res.cookies).toHaveLength(0);
  });

  it('gives an identical response for an already-registered email and notifies the owner', async () => {
    const first = await post(ctx, '/api/auth/register', { email: EMAIL, password: PASSWORD });
    const second = await post(ctx, '/api/auth/register', { email: EMAIL, password: 'a different long password' });
    expect(second.statusCode).toBe(first.statusCode);
    expect(second.body).toBe(first.body);
    expect(await ctx.db.select().from(users)).toHaveLength(1);
    expect(ctx.mailer.lastTo(EMAIL)?.subject).toMatch(/already|tried/i);
  });

  it('normalises email case so sign-in is case-insensitive', async () => {
    await registerAndVerify(ctx, 'Owner@Example.COM', PASSWORD);
    const [user] = await ctx.db.select().from(users);
    expect(user?.email).toBe(EMAIL);
    await login(ctx, 'OWNER@example.com', PASSWORD);
  });

  it('rejects emails padded with whitespace rather than guessing', async () => {
    const res = await post(ctx, '/api/auth/register', { email: '  owner@example.com ', password: PASSWORD });
    expect(res.statusCode).toBe(400);
  });

  it('accepts a verification token only once', async () => {
    await post(ctx, '/api/auth/register', { email: EMAIL, password: PASSWORD });
    const token = tokenFromMail(ctx.mailer.lastTo(EMAIL)?.text);
    expect((await post(ctx, '/api/auth/verify-email', { token })).statusCode).toBe(200);
    const again = await post(ctx, '/api/auth/verify-email', { token });
    expect(again.statusCode).toBe(400);
    expect(again.json().error).toBe('invalid_token');
  });

  it('stores only a hash of the emailed token', async () => {
    await post(ctx, '/api/auth/register', { email: EMAIL, password: PASSWORD });
    const token = tokenFromMail(ctx.mailer.lastTo(EMAIL)?.text);
    const rows = await ctx.db.select().from(userTokens);
    expect(rows).toHaveLength(1);
    expect(rows[0]!.tokenHash).not.toContain(token);
    expect(rows[0]!.tokenHash).toMatch(/^[0-9a-f]{64}$/);
  });
});

describe('sessions', () => {
  beforeEach(async () => {
    await registerAndVerify(ctx, EMAIL, PASSWORD);
  });

  it('signs in with a hardened cookie and signs out', async () => {
    const res = await post(ctx, '/api/auth/login', { email: EMAIL, password: PASSWORD });
    expect(res.statusCode).toBe(200);
    expect(res.json().user).toMatchObject({ email: EMAIL, emailVerified: true, plan: 'free' });
    expect(res.json().user.passwordHash).toBeUndefined();

    const cookie = res.cookies.find((c) => c.name === 'shc_session')!;
    expect(cookie.httpOnly).toBe(true);
    expect(cookie.secure).toBe(true);
    expect(cookie.sameSite).toBe('Lax');
    expect(cookie.path).toBe('/');

    // Only the hash of the cookie value is stored.
    const [stored] = await ctx.db.select().from(sessions);
    expect(stored!.idHash).not.toBe(cookie.value);

    const header = `shc_session=${cookie.value}`;
    const me = await ctx.app.inject({ method: 'GET', url: '/api/auth/me', headers: { cookie: header } });
    expect(me.statusCode).toBe(200);
    expect(me.json().user.email).toBe(EMAIL);

    const out = await post(ctx, '/api/auth/logout', {}, header);
    expect(out.statusCode).toBe(204);
    expect(await ctx.db.select().from(sessions)).toHaveLength(0);
    const events = (await ctx.db.select().from(auditEvents)).map((e) => e.event);
    expect(events).toEqual(expect.arrayContaining(['register', 'email_verified', 'login', 'logout']));

    const after = await ctx.app.inject({ method: 'GET', url: '/api/auth/me', headers: { cookie: header } });
    expect(after.statusCode).toBe(401);
  });

  it('gives the same answer for a wrong password and an unknown email', async () => {
    const wrong = await post(ctx, '/api/auth/login', { email: EMAIL, password: 'not the password at all' });
    const unknown = await post(ctx, '/api/auth/login', { email: 'nobody@example.com', password: PASSWORD });
    expect(wrong.statusCode).toBe(401);
    expect(unknown.statusCode).toBe(401);
    expect(wrong.body).toBe(unknown.body);
  });

  it(`locks the account after ${MAX_FAILED_LOGINS} failed attempts and recovers when the lock expires`, async () => {
    for (let i = 0; i < MAX_FAILED_LOGINS; i++) {
      await post(ctx, '/api/auth/login', { email: EMAIL, password: `wrong password ${i}` });
    }
    const locked = await post(ctx, '/api/auth/login', { email: EMAIL, password: PASSWORD });
    expect(locked.statusCode).toBe(401);
    expect(locked.json().error).toBe('invalid_credentials');

    const lockEvents = await ctx.db.select().from(auditEvents).where(eq(auditEvents.event, 'login_locked'));
    expect(lockEvents).toHaveLength(1);

    // Simulate the lockout window passing.
    await ctx.db.update(users).set({ lockedUntil: new Date(Date.now() - 1000) }).where(eq(users.email, EMAIL));
    await login(ctx, EMAIL, PASSWORD);
    const [user] = await ctx.db.select().from(users).where(eq(users.email, EMAIL));
    expect(user?.failedLogins).toBe(0);
    expect(user?.lockedUntil).toBeNull();
  });

  it('replaces an existing session on a new sign-in', async () => {
    const first = await login(ctx, EMAIL, PASSWORD);
    await post(ctx, '/api/auth/login', { email: EMAIL, password: PASSWORD }, first);
    expect(await ctx.db.select().from(sessions)).toHaveLength(1);
    const stale = await ctx.app.inject({ method: 'GET', url: '/api/auth/me', headers: { cookie: first } });
    expect(stale.statusCode).toBe(401);
  });
});

describe('password reset', () => {
  beforeEach(async () => {
    await registerAndVerify(ctx, EMAIL, PASSWORD);
    ctx.mailer.sent.length = 0;
  });

  it('answers the same for unknown emails without sending anything', async () => {
    const known = await post(ctx, '/api/auth/password/forgot', { email: EMAIL });
    const unknown = await post(ctx, '/api/auth/password/forgot', { email: 'nobody@example.com' });
    expect(unknown.statusCode).toBe(202);
    expect(unknown.body).toBe(known.body);
    expect(ctx.mailer.sent.map((m) => m.to)).toEqual([EMAIL]);
  });

  it('sets a new password, signs out every session and burns the token', async () => {
    const session = await login(ctx, EMAIL, PASSWORD);
    await post(ctx, '/api/auth/password/forgot', { email: EMAIL });
    const token = tokenFromMail(ctx.mailer.lastTo(EMAIL)?.text);

    const NEW_PASSWORD = 'an entirely new passphrase';
    const res = await post(ctx, '/api/auth/password/reset', { token, password: NEW_PASSWORD });
    expect(res.statusCode).toBe(200);

    const me = await ctx.app.inject({ method: 'GET', url: '/api/auth/me', headers: { cookie: session } });
    expect(me.statusCode).toBe(401);

    expect((await post(ctx, '/api/auth/login', { email: EMAIL, password: PASSWORD })).statusCode).toBe(401);
    await login(ctx, EMAIL, NEW_PASSWORD);

    const reuse = await post(ctx, '/api/auth/password/reset', { token, password: 'yet another long password' });
    expect(reuse.statusCode).toBe(400);
  });

  it('invalidates an older reset link when a new one is requested', async () => {
    await post(ctx, '/api/auth/password/forgot', { email: EMAIL });
    const oldToken = tokenFromMail(ctx.mailer.lastTo(EMAIL)?.text);
    await post(ctx, '/api/auth/password/forgot', { email: EMAIL });

    const res = await post(ctx, '/api/auth/password/reset', { token: oldToken, password: 'a fresh long passphrase' });
    expect(res.statusCode).toBe(400);

    const live = await ctx.db
      .select()
      .from(userTokens)
      .where(and(eq(userTokens.purpose, 'password_reset')));
    expect(live.filter((t) => t.usedAt === null)).toHaveLength(1);
  });
});
