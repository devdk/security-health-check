import type { FastifyPluginAsyncTypebox } from '@fastify/type-provider-typebox';
import type { FastifyRequest } from 'fastify';
import { Type, type TSchema } from 'typebox';
import { requestContext } from '../lib/request-context';
import { requireAuth } from '../plugins/session';
import type { ReportService } from '../services/report-service';

const Nullable = <T extends TSchema>(s: T) => Type.Union([s, Type.Null()]);
const Severity = Type.Union([Type.Literal('critical'), Type.Literal('high'), Type.Literal('medium'), Type.Literal('low'), Type.Literal('info')]);
const Confidence = Type.Union([Type.Literal('confirmed'), Type.Literal('likely'), Type.Literal('possible')]);
const SoftwareType = Type.Union([Type.Literal('core'), Type.Literal('plugin'), Type.Literal('theme'), Type.Literal('php'), Type.Literal('web_server')]);
const Standard = Type.Object({ id: Type.String(), name: Type.String(), url: Type.String() });
const Component = Type.Object({ type: SoftwareType, slug: Type.String(), name: Nullable(Type.String()), version: Nullable(Type.String()) });

/** Exactly what a free user may learn about a locked finding. Extra fields are stripped. */
const LockedFinding = Type.Object(
  { id: Type.String(), locked: Type.Literal(true), severity: Severity, category: Type.String() },
  { additionalProperties: false },
);

const RevealedFinding = Type.Object(
  {
    id: Type.String(),
    locked: Type.Literal(false),
    severity: Severity,
    confidence: Confidence,
    title: Type.String(),
    conceptId: Type.String(),
    category: Type.String(),
    explanation: Type.String(),
    evidence: Type.Record(Type.String(), Type.Unknown()),
    fix: Nullable(
      Type.Array(
        Type.Object({
          title: Type.String(),
          summary: Type.String(),
          effort: Type.Union([Type.Literal('minutes'), Type.Literal('hour'), Type.Literal('day')]),
          steps: Type.Array(Type.String()),
        }),
      ),
    ),
    fixLocked: Type.Boolean(),
    fixNote: Nullable(Type.String()),
    references: Type.Array(Type.Object({ type: Type.String(), id: Type.Optional(Type.String()), url: Type.Optional(Type.String()) })),
    standards: Type.Object({ weaknesses: Type.Array(Standard), attackPatterns: Type.Array(Standard), owasp: Type.Array(Type.Object({ id: Type.String(), name: Type.String() })) }),
    component: Nullable(Component),
    indicatesCompromise: Type.Boolean(),
    attribution: Nullable(Type.Object({ source: Type.String(), recordUrl: Nullable(Type.String()), notices: Type.Array(Type.String()) })),
    fixRequest: Nullable(Type.Object({ status: Type.String(), createdAt: Type.String() })),
    source: Type.Union([Type.Literal('outside'), Type.Literal('inside')]),
  },
  { additionalProperties: false },
);

const Report = Type.Object({
  scanId: Type.String(),
  siteId: Type.String(),
  domain: Type.String(),
  status: Type.String(),
  createdAt: Type.String(),
  startedAt: Nullable(Type.String()),
  finishedAt: Nullable(Type.String()),
  baseUrl: Nullable(Type.String()),
  requestCount: Type.Integer(),
  kind: Type.Union([Type.Literal('external'), Type.Literal('inside')]),
  outside: Nullable(Type.Object({ scanId: Type.String(), finishedAt: Type.String(), baseUrl: Nullable(Type.String()), requestCount: Type.Integer() }, { additionalProperties: false })),
  inside: Nullable(Type.Object({ scanId: Type.String(), finishedAt: Type.String(), pluginVersion: Nullable(Type.String()) }, { additionalProperties: false })),
  plan: Type.Union([Type.Literal('free'), Type.Literal('pro')]),
  score: Type.Integer({ minimum: 0, maximum: 100 }),
  grade: Type.String(),
  counts: Type.Object({ critical: Type.Integer(), high: Type.Integer(), medium: Type.Integer(), low: Type.Integer(), info: Type.Integer() }),
  compromiseSuspected: Type.Boolean(),
  lockedCount: Type.Integer(),
  findings: Type.Array(Type.Union([LockedFinding, RevealedFinding])),
  components: Type.Array(Type.Intersect([Component, Type.Object({ versionConfidence: Nullable(Confidence), active: Nullable(Type.Boolean()) })])),
  dataSources: Type.Array(
    Type.Object({
      id: Type.String(),
      name: Type.String(),
      url: Type.String(),
      notice: Nullable(Type.String()),
      licenses: Type.Array(Type.Object({ holder: Type.String(), notice: Type.String(), license: Type.String(), licenseUrl: Type.String() })),
    }),
  ),
  features: Type.Object({ pdf: Type.Boolean(), history: Type.Boolean(), fixRequests: Type.Boolean(), weeklyScans: Type.Boolean() }),
});

const ScanParams = Type.Object({ scanId: Type.String({ format: 'uuid' }) }, { additionalProperties: false });
const FindingParams = Type.Object({ findingId: Type.String({ format: 'uuid' }) }, { additionalProperties: false });
const owner = (req: FastifyRequest) => req.auth!.userId;

/** Mounted under /api. */
export const reportRoutes: FastifyPluginAsyncTypebox<{ reports: ReportService }> = async (app, { reports }) => {
  app.addHook('preHandler', requireAuth);

  app.get('/scans/:scanId/report', { schema: { params: ScanParams, response: { 200: Type.Object({ report: Report }) } } }, async (req) => ({
    report: await reports.report(owner(req), req.params.scanId),
  }));

  app.get(
    '/scans/:scanId/report.pdf',
    { config: { rateLimit: { max: 10, timeWindow: '1 minute', keyGenerator: (req: FastifyRequest) => `pdf:${req.auth?.userId ?? req.ip}` } }, schema: { params: ScanParams } },
    async (req, reply) => {
      const { pdf, filename } = await reports.pdf(owner(req), req.params.scanId, requestContext(req));
      return reply
        .header('content-type', 'application/pdf')
        .header('content-disposition', `attachment; filename="${filename}"`)
        .header('x-content-type-options', 'nosniff')
        .send(pdf);
    },
  );

  app.post(
    '/findings/:findingId/fix-request',
    {
      config: { rateLimit: { max: 20, timeWindow: '1 hour', keyGenerator: (req: FastifyRequest) => `fix:${req.auth?.userId ?? req.ip}` } },
      schema: {
        params: FindingParams,
        body: Type.Object({ message: Type.String({ maxLength: 2000 }) }, { additionalProperties: false }),
        response: { 200: Type.Object({ request: Type.Object({ id: Type.String(), status: Type.String(), createdAt: Type.String() }), created: Type.Boolean() }) },
      },
    },
    async (req) => {
      const { request, created } = await reports.requestFix(owner(req), req.params.findingId, req.body.message.trim(), requestContext(req));
      return { request: { id: request.id, status: request.status, createdAt: request.createdAt.toISOString() }, created };
    },
  );
};
