import type { FastifyPluginAsyncTypebox } from '@fastify/type-provider-typebox';
import type { FastifyRequest } from 'fastify';
import { Type, type TSchema } from 'typebox';
import { REPORT_MAX_BYTES } from '@shc/companion';
import type { Config } from '@shc/config';
import { requestContext } from '../lib/request-context';
import { authRouteLimit } from '../plugins/rate-limit';
import { requireAuth } from '../plugins/session';
import type { PluginService } from '../services/plugin-service';

const Nullable = <T extends TSchema>(schema: T) => Type.Union([schema, Type.Null()]);
const strict = { additionalProperties: false } as const;

const PluginStatus = Type.Object(
  {
    available: Type.Boolean(),
    status: Type.Union([Type.Literal('not_connected'), Type.Literal('connected'), Type.Literal('expired')]),
    connectedAt: Nullable(Type.String()),
    expiresAt: Nullable(Type.String()),
    lastReportAt: Nullable(Type.String()),
    lastScanId: Nullable(Type.String()),
    pluginVersion: Nullable(Type.String()),
  },
  strict,
);
const StatusResponse = Type.Object({ plugin: PluginStatus }, strict);
const SiteParams = Type.Object({ siteId: Type.String({ format: 'uuid' }) }, strict);
const owner = (req: FastifyRequest) => req.auth!.userId;

/** Mounted under /api/sites: the owner's view of the companion plugin for one site. */
export const sitePluginRoutes: FastifyPluginAsyncTypebox<{ plugins: PluginService }> = async (app, { plugins }) => {
  app.addHook('preHandler', requireAuth);

  app.get('/:siteId/plugin', { schema: { params: SiteParams, response: { 200: StatusResponse } } }, async (req) => ({
    plugin: await plugins.status(owner(req), req.params.siteId),
  }));

  app.post(
    '/:siteId/plugin/pairing-code',
    {
      config: { rateLimit: { max: 10, timeWindow: '1 minute', keyGenerator: (req: FastifyRequest) => `pairing-code:${req.auth?.userId ?? req.ip}` } },
      schema: {
        params: SiteParams,
        response: { 201: Type.Object({ pairing: Type.Object({ code: Type.String(), expiresAt: Type.String(), serviceUrl: Type.String() }, strict) }, strict) },
      },
    },
    async (req, reply) => reply.code(201).send({ pairing: await plugins.createPairingCode(owner(req), req.params.siteId, requestContext(req)) }),
  );

  app.delete('/:siteId/plugin', { schema: { params: SiteParams, response: { 200: StatusResponse } } }, async (req) => ({
    plugin: await plugins.disconnect(owner(req), req.params.siteId, requestContext(req)),
  }));
};

/** Mounted under /api/plugin: called by the plugin itself, without a session. */
export const pluginRoutes: FastifyPluginAsyncTypebox<{ config: Config; plugins: PluginService }> = async (app, { config, plugins }) => {
  app.post(
    '/pair',
    {
      config: authRouteLimit(config),
      schema: {
        body: Type.Object(
          {
            code: Type.String({ minLength: 1, maxLength: 64 }),
            homeUrl: Type.String({ minLength: 1, maxLength: 2000 }),
            pluginVersion: Type.String({ minLength: 1, maxLength: 64, pattern: '^[0-9A-Za-z.+_-]+$' }),
          },
          strict,
        ),
        response: { 201: Type.Object({ keyId: Type.String(), key: Type.String(), expiresAt: Type.String() }, strict) },
      },
    },
    async (req, reply) => reply.code(201).send(await plugins.pair(req.body, requestContext(req))),
  );

  // Signatures cover the exact bytes sent, so this route alone keeps the body raw.
  await app.register(async (reports) => {
    reports.removeAllContentTypeParsers();
    reports.addContentTypeParser('application/json', { parseAs: 'buffer' }, (_req, body, done) => done(null, body));

    reports.post(
      '/reports',
      {
        bodyLimit: REPORT_MAX_BYTES,
        schema: { response: { 202: Type.Object({ reportId: Type.String(), scanId: Type.String() }, strict) } },
      },
      async (req, reply) => {
        const body = Buffer.isBuffer(req.body) ? req.body : Buffer.alloc(0);
        return reply.code(202).send(await plugins.receiveReport(req.headers, body, requestContext(req)));
      },
    );
  });
};
