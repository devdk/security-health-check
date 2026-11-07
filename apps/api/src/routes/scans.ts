import type { FastifyPluginAsyncTypebox } from '@fastify/type-provider-typebox';
import type { FastifyRequest } from 'fastify';
import { Type, type TSchema } from 'typebox';
import { HttpError } from '../lib/errors';
import { requestContext } from '../lib/request-context';
import { requireAuth } from '../plugins/session';
import type { ScanService } from '../services/scan-service';

const Nullable = <T extends TSchema>(schema: T) => Type.Union([schema, Type.Null()]);
const ScanStatus = Type.Union([Type.Literal('queued'), Type.Literal('running'), Type.Literal('completed'), Type.Literal('failed')]);
const ScanTrigger = Type.Union([Type.Literal('manual'), Type.Literal('scheduled'), Type.Literal('plugin')]);
const SoftwareType = Type.Union([Type.Literal('core'), Type.Literal('plugin'), Type.Literal('theme'), Type.Literal('php'), Type.Literal('web_server')]);
const Confidence = Type.Union([Type.Literal('confirmed'), Type.Literal('likely'), Type.Literal('possible')]);
const ModuleStatus = Type.Union([Type.Literal('ok'), Type.Literal('skipped'), Type.Literal('failed'), Type.Literal('budget_exhausted')]);

const Counts = Type.Object({
  critical: Type.Integer(),
  high: Type.Integer(),
  medium: Type.Integer(),
  low: Type.Integer(),
  info: Type.Integer(),
});

export const ScanSummary = Type.Object({
  id: Type.String(),
  siteId: Type.String(),
  status: ScanStatus,
  trigger: ScanTrigger,
  createdAt: Type.String(),
  startedAt: Nullable(Type.String()),
  finishedAt: Nullable(Type.String()),
  requestCount: Type.Integer(),
  baseUrl: Nullable(Type.String()),
  error: Nullable(Type.String()),
  findingCounts: Counts,
});

const ScanDetail = Type.Intersect([
  ScanSummary,
  Type.Object({
    domain: Type.String(),
    components: Type.Array(
      Type.Object({
        type: SoftwareType,
        slug: Type.String(),
        name: Nullable(Type.String()),
        version: Nullable(Type.String()),
        versionConfidence: Nullable(Confidence),
      }),
    ),
    modules: Type.Array(
      Type.Object({
        module: Type.String(),
        status: ModuleStatus,
        durationMs: Type.Integer(),
        requests: Type.Integer(),
        findings: Type.Integer(),
        note: Type.Optional(Type.String()),
      }),
    ),
  }),
]);

const SiteParams = Type.Object({ siteId: Type.String({ format: 'uuid' }) }, { additionalProperties: false });
const ScanParams = Type.Object({ scanId: Type.String({ format: 'uuid' }) }, { additionalProperties: false });
const owner = (req: FastifyRequest) => req.auth!.userId;

/** Mounted under /api/sites: start and list scans for one site. */
export const siteScanRoutes: FastifyPluginAsyncTypebox<{ scans: ScanService }> = async (app, { scans }) => {
  app.addHook('preHandler', requireAuth);

  app.post(
    '/:siteId/scans',
    {
      config: { rateLimit: { max: 10, timeWindow: '1 minute', keyGenerator: (req: FastifyRequest) => `scan:${req.auth?.userId ?? req.ip}` } },
      schema: { params: SiteParams, response: { 202: Type.Object({ scan: ScanSummary }) } },
    },
    async (req, reply) => {
      try {
        const { scan } = await scans.request(owner(req), req.params.siteId, requestContext(req));
        return reply.code(202).send({ scan });
      } catch (err) {
        const retryAfter = (err as { retryAfter?: number }).retryAfter;
        if (err instanceof HttpError && retryAfter) reply.header('Retry-After', String(retryAfter));
        throw err;
      }
    },
  );

  app.get('/:siteId/scans', { schema: { params: SiteParams, response: { 200: Type.Object({ scans: Type.Array(ScanSummary) }) } } }, async (req) => ({
    scans: await scans.listForSite(owner(req), req.params.siteId),
  }));
};

/** Mounted under /api/scans. */
export const scanRoutes: FastifyPluginAsyncTypebox<{ scans: ScanService }> = async (app, { scans }) => {
  app.addHook('preHandler', requireAuth);

  app.get('/:scanId', { schema: { params: ScanParams, response: { 200: Type.Object({ scan: ScanDetail }) } } }, async (req) => ({
    scan: await scans.get(owner(req), req.params.scanId),
  }));
};
