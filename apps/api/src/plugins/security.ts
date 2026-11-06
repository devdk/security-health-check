import helmet from '@fastify/helmet';
import type { FastifyInstance } from 'fastify';
import type { Config } from '@shc/config';
import { HttpError } from '../lib/errors';

const UNSAFE_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

/**
 * Baseline HTTP hardening for a JSON API:
 * - strict security headers and no caching of API responses
 * - JSON-only bodies (Fastify's default text/plain parser is removed, so a cross-site
 *   HTML form cannot reach handlers)
 * - Origin check on state-changing requests (CSRF defence on top of SameSite cookies)
 */
export async function registerSecurity(app: FastifyInstance, config: Config): Promise<void> {
  await app.register(helmet, {
    contentSecurityPolicy: {
      useDefaults: false,
      directives: { defaultSrc: ["'none'"], frameAncestors: ["'none'"], baseUri: ["'none'"], formAction: ["'none'"] },
    },
    crossOriginResourcePolicy: { policy: 'same-origin' },
    referrerPolicy: { policy: 'no-referrer' },
    strictTransportSecurity: { maxAge: 31_536_000, includeSubDomains: true },
  });

  app.removeContentTypeParser('text/plain');

  const allowed = new Set(config.web.allowedOrigins);

  app.addHook('onRequest', async (request) => {
    if (!UNSAFE_METHODS.has(request.method)) return;
    const origin = request.headers.origin;
    if (origin !== undefined) {
      if (!allowed.has(origin)) throw new HttpError(403, 'forbidden_origin', 'Request origin not allowed');
      return;
    }
    // Browsers send Origin on cross-site POSTs; treat an explicit cross-site fetch without one as hostile.
    if (request.headers['sec-fetch-site'] === 'cross-site') {
      throw new HttpError(403, 'forbidden_origin', 'Request origin not allowed');
    }
  });

  app.addHook('onSend', async (_request, reply, payload) => {
    reply.header('Cache-Control', 'no-store');
    return payload;
  });
}
