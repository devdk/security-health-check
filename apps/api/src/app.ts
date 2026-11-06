import { randomUUID } from 'node:crypto';
import Fastify, { type FastifyServerOptions } from 'fastify';
import type { TypeBoxTypeProvider } from '@fastify/type-provider-typebox';
import type { Redis } from 'ioredis';
import type { Config } from '@shc/config';
import type { Database } from '@shc/db';
import { ConsoleMailer, type Mailer } from './lib/mailer';
import { registerErrorHandling } from './plugins/errors';
import { registerRateLimit } from './plugins/rate-limit';
import { registerSecurity } from './plugins/security';
import { registerSession } from './plugins/session';
import { authRoutes } from './routes/auth';
import { healthRoutes } from './routes/health';
import { AuthService } from './services/auth-service';
import { SessionService } from './services/session-service';
import { UserTokenService } from './services/user-token-service';

export interface AppDeps {
  config: Config;
  db: Database;
  redis: Redis;
  /** Defaults to the transport named in config (console in development). */
  mailer?: Mailer;
  logger?: FastifyServerOptions['logger'];
}

/** Builds the API without listening, so tests can drive it with app.inject(). */
export async function buildApp(deps: AppDeps) {
  const { config, db, redis } = deps;

  const app = Fastify({
    logger: deps.logger ?? {
      level: config.logLevel,
      redact: ['req.headers.cookie', 'req.headers.authorization', 'res.headers["set-cookie"]'],
    },
    // Trust exactly N proxy hops (nginx in Docker), so clients can't spoof X-Forwarded-For.
    trustProxy: (_address: string, hop: number) => hop < config.api.trustProxyHops,
    bodyLimit: 64 * 1024,
    genReqId: () => randomUUID(),
    ajv: { customOptions: { removeAdditional: 'all', allErrors: false } },
  }).withTypeProvider<TypeBoxTypeProvider>();

  registerErrorHandling(app);
  await registerSecurity(app, config);

  const mailer = deps.mailer ?? new ConsoleMailer(app.log);

  const sessions = new SessionService(db, config.session.ttlHours);
  const tokens = new UserTokenService(db);
  const auth = new AuthService({ db, config, mailer, sessions, tokens });

  const cookies = await registerSession(app, config, sessions);
  await registerRateLimit(app, config, redis);

  await app.register(healthRoutes, { prefix: '/api', db, redis });
  await app.register(authRoutes, { prefix: '/api/auth', config, auth, sessions, cookies });

  return app;
}

export type App = Awaited<ReturnType<typeof buildApp>>;
