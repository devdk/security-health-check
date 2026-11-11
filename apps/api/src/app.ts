import { randomUUID } from 'node:crypto';
import Fastify, { type FastifyServerOptions } from 'fastify';
import type { TypeBoxTypeProvider } from '@fastify/type-provider-typebox';
import type { Redis } from 'ioredis';
import type { Config } from '@shc/config';
import { BullScanQueue, NoPaymentProvider, redisConnection, StubPaymentProvider, type PaymentProvider, type ScanQueue } from '@shc/core';
import type { Database } from '@shc/db';
import { createTxtResolver, OwnershipVerifier, SafeFetcher, type OwnershipChecker } from '@shc/net';
import { ConsoleMailer, type Mailer } from './lib/mailer';
import { GotenbergPdfRenderer, noPdf, type PdfRenderer } from './lib/pdf';
import { registerErrorHandling } from './plugins/errors';
import { registerRateLimit } from './plugins/rate-limit';
import { registerSecurity } from './plugins/security';
import { registerSession } from './plugins/session';
import { authRoutes } from './routes/auth';
import { billingRoutes } from './routes/billing';
import { healthRoutes } from './routes/health';
import { pluginRoutes, sitePluginRoutes } from './routes/plugin';
import { reportRoutes } from './routes/report';
import { scanRoutes, siteScanRoutes } from './routes/scans';
import { siteRoutes } from './routes/sites';
import { AuthService } from './services/auth-service';
import { PluginService } from './services/plugin-service';
import { ReportService } from './services/report-service';
import { ScanService } from './services/scan-service';
import { SessionService } from './services/session-service';
import { SiteService } from './services/site-service';
import { UserTokenService } from './services/user-token-service';

export interface AppDeps {
  config: Config;
  db: Database;
  redis: Redis;
  /** Defaults to the transport named in config (console in development). */
  mailer?: Mailer;
  /** Defaults to real DNS + SSRF-safe HTTP checks. Tests inject a fake. */
  ownership?: OwnershipChecker;
  /** Defaults to the BullMQ queue in Redis. Tests inject a fake. */
  scanQueue?: ScanQueue;
  /** Defaults to the Gotenberg service when PDF_SERVICE_URL is set. */
  pdf?: PdfRenderer;
  /** Defaults to the provider named in config (the stub in development). */
  payments?: PaymentProvider;
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

  const ownership =
    deps.ownership ??
    new OwnershipVerifier({
      fetcher: new SafeFetcher({ userAgent: config.scanner.userAgent, allowPrivateHosts: config.scanner.allowPrivateHosts }),
      resolveTxt: createTxtResolver({ servers: config.scanner.dnsResolvers }),
    });
  const siteService = new SiteService({ db, ownership, allowHosts: config.scanner.allowPrivateHosts });
  const scanQueue = deps.scanQueue ?? new BullScanQueue(redisConnection(config.redisUrl));
  if (!deps.scanQueue) app.addHook('onClose', () => scanQueue.close());
  const scanService = new ScanService({ db, ownership, queue: scanQueue, cooldownMinutes: config.scan.cooldownMinutes });
  const pdf = deps.pdf ?? (config.pdf.serviceUrl ? new GotenbergPdfRenderer(config.pdf.serviceUrl) : noPdf);
  const reportService = new ReportService({ db, pdf });
  const pluginService = new PluginService({ db, ownership, redis, queue: scanQueue, plugin: config.plugin, serviceUrl: config.web.baseUrl });
  const payments = deps.payments ?? (config.payments.provider === 'stub' ? new StubPaymentProvider(db) : new NoPaymentProvider());

  const cookies = await registerSession(app, config, sessions);
  await registerRateLimit(app, config, redis);

  await app.register(healthRoutes, { prefix: '/api', db, redis });
  await app.register(authRoutes, { prefix: '/api/auth', config, auth, sessions, cookies });
  await app.register(siteRoutes, { prefix: '/api/sites', sites: siteService });
  await app.register(siteScanRoutes, { prefix: '/api/sites', scans: scanService });
  await app.register(scanRoutes, { prefix: '/api/scans', scans: scanService });
  await app.register(reportRoutes, { prefix: '/api', reports: reportService });
  await app.register(billingRoutes, { prefix: '/api/billing', db, payments });
  await app.register(sitePluginRoutes, { prefix: '/api/sites', plugins: pluginService });
  await app.register(pluginRoutes, { prefix: '/api/plugin', config, plugins: pluginService });

  return app;
}

export type App = Awaited<ReturnType<typeof buildApp>>;
