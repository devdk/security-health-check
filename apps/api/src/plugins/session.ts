import cookie from '@fastify/cookie';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import type { Config } from '@shc/config';
import { unauthorised } from '../lib/errors';
import type { SessionService } from '../services/session-service';

export interface RequestAuth {
  userId: string;
  sessionIdHash: string;
}

declare module 'fastify' {
  interface FastifyRequest {
    auth: RequestAuth | null;
  }
}

export interface SessionCookieOps {
  set(reply: FastifyReply, token: string): void;
  clear(reply: FastifyReply): void;
}

export async function registerSession(
  app: FastifyInstance,
  config: Config,
  sessions: SessionService,
): Promise<SessionCookieOps> {
  await app.register(cookie);

  const { cookieName, cookieSecure } = config.session;
  const baseOptions = { httpOnly: true, secure: cookieSecure, sameSite: 'lax' as const, path: '/' };

  const ops: SessionCookieOps = {
    set: (reply, token) => reply.setCookie(cookieName, token, { ...baseOptions, maxAge: sessions.ttlSeconds }),
    clear: (reply) => reply.clearCookie(cookieName, baseOptions),
  };

  app.decorateRequest('auth', null);

  app.addHook('onRequest', async (request, reply) => {
    const token = request.cookies[cookieName];
    if (!token) return;
    const session = await sessions.resolve(token);
    if (!session) {
      ops.clear(reply);
      return;
    }
    request.auth = { userId: session.userId, sessionIdHash: session.idHash };
    if (session.extended) ops.set(reply, token);
  });

  return ops;
}

/** preHandler that rejects requests without a valid session. */
export async function requireAuth(request: FastifyRequest): Promise<void> {
  if (!request.auth) throw unauthorised();
}
