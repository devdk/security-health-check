import type { FastifyPluginAsyncTypebox } from '@fastify/type-provider-typebox';
import { Type } from 'typebox';
import type { Config } from '@shc/config';
import { PASSWORD_MAX_LENGTH, PASSWORD_MIN_LENGTH } from '@shc/shared';
import { HttpError } from '../lib/errors';
import type { SessionCookieOps } from '../plugins/session';
import { requireAuth } from '../plugins/session';
import { authRouteLimit } from '../plugins/rate-limit';
import type { AuthService, RequestContext } from '../services/auth-service';
import type { SessionService } from '../services/session-service';

export interface AuthRouteDeps {
  config: Config;
  auth: AuthService;
  sessions: SessionService;
  cookies: SessionCookieOps;
}

const Email = Type.String({ format: 'email', minLength: 3, maxLength: 254 });
const Password = Type.String({ minLength: PASSWORD_MIN_LENGTH, maxLength: PASSWORD_MAX_LENGTH });
// Login accepts any length so old passwords keep working if the policy changes; capped to stop hashing huge inputs.
const LoginPassword = Type.String({ minLength: 1, maxLength: PASSWORD_MAX_LENGTH });
const Token = Type.String({ minLength: 43, maxLength: 43, pattern: '^[A-Za-z0-9_-]+$' });

const PublicUser = Type.Object({
  id: Type.String(),
  email: Type.String(),
  emailVerified: Type.Boolean(),
  plan: Type.Union([Type.Literal('free'), Type.Literal('pro')]),
});

const Message = Type.Object({ message: Type.String() });
const strict = { additionalProperties: false } as const;

export const authRoutes: FastifyPluginAsyncTypebox<AuthRouteDeps> = async (app, { config, auth, sessions, cookies }) => {
  const limited = authRouteLimit(config);
  const ctx = (req: { ip: string; headers: Record<string, unknown> }): RequestContext => ({
    ip: req.ip,
    userAgent: typeof req.headers['user-agent'] === 'string' ? req.headers['user-agent'] : undefined,
  });

  app.post(
    '/register',
    {
      config: limited,
      schema: {
        body: Type.Object({ email: Email, password: Password }, strict),
        response: { 202: Message },
      },
    },
    async (req, reply) => {
      await auth.register(req.body.email, req.body.password, ctx(req));
      return reply.code(202).send({ message: 'Check your email to confirm your address.' });
    },
  );

  app.post(
    '/verify-email',
    {
      config: limited,
      schema: { body: Type.Object({ token: Token }, strict), response: { 200: Message } },
    },
    async (req) => {
      const ok = await auth.verifyEmail(req.body.token, ctx(req));
      if (!ok) throw new HttpError(400, 'invalid_token', 'This link is invalid or has expired');
      return { message: 'Email confirmed. You can now sign in.' };
    },
  );

  app.post(
    '/verify-email/resend',
    {
      config: limited,
      schema: { body: Type.Object({ email: Email }, strict), response: { 202: Message } },
    },
    async (req, reply) => {
      await auth.resendVerification(req.body.email);
      return reply.code(202).send({ message: 'If that account needs confirming, we have sent a new link.' });
    },
  );

  app.post(
    '/login',
    {
      config: limited,
      schema: {
        body: Type.Object({ email: Email, password: LoginPassword }, strict),
        response: { 200: Type.Object({ user: PublicUser }) },
      },
    },
    async (req, reply) => {
      // Drop any session the browser already holds before issuing a new one (prevents fixation).
      if (req.auth) await sessions.destroy(req.auth.sessionIdHash);
      const { user, token } = await auth.login(req.body.email, req.body.password, ctx(req));
      cookies.set(reply, token);
      return { user };
    },
  );

  app.post('/logout', { schema: { response: { 204: Type.Null() } } }, async (req, reply) => {
    if (req.auth) await auth.logout(req.auth, ctx(req));
    cookies.clear(reply);
    return reply.code(204).send(null);
  });

  app.get(
    '/me',
    { preHandler: requireAuth, schema: { response: { 200: Type.Object({ user: PublicUser }) } } },
    async (req) => ({ user: await auth.getPublicUser(req.auth!.userId) }),
  );

  app.post(
    '/password/forgot',
    {
      config: limited,
      schema: { body: Type.Object({ email: Email }, strict), response: { 202: Message } },
    },
    async (req, reply) => {
      await auth.requestPasswordReset(req.body.email, ctx(req));
      return reply.code(202).send({ message: 'If an account exists for that email, we have sent a reset link.' });
    },
  );

  app.post(
    '/password/reset',
    {
      config: limited,
      schema: { body: Type.Object({ token: Token, password: Password }, strict), response: { 200: Message } },
    },
    async (req, reply) => {
      const ok = await auth.resetPassword(req.body.token, req.body.password, ctx(req));
      if (!ok) throw new HttpError(400, 'invalid_token', 'This link is invalid or has expired');
      cookies.clear(reply);
      return { message: 'Password updated. Sign in with your new password.' };
    },
  );
};
