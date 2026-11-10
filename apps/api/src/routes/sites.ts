import type { FastifyPluginAsyncTypebox } from '@fastify/type-provider-typebox';
import type { FastifyRequest } from 'fastify';
import { Type, type TSchema } from 'typebox';
import { requestContext } from '../lib/request-context';
import { requireAuth } from '../plugins/session';
import type { SiteService } from '../services/site-service';

const Nullable = <T extends TSchema>(schema: T) => Type.Union([schema, Type.Null()]);
const Method = Type.Union([Type.Literal('dns_txt'), Type.Literal('file')]);

const Site = Type.Object({
  id: Type.String(),
  domain: Type.String(),
  status: Type.Union([Type.Literal('verified'), Type.Literal('stale'), Type.Literal('unverified')]),
  verificationMethod: Nullable(Method),
  verifiedAt: Nullable(Type.String()),
  lastVerifyAttemptAt: Nullable(Type.String()),
  lastVerifyError: Nullable(Type.String()),
  createdAt: Type.String(),
  weeklyScan: Type.Boolean(),
  nextScanAt: Nullable(Type.String()),
  instructions: Type.Object({
    dns: Type.Object({ name: Type.String(), type: Type.Literal('TXT'), value: Type.String() }),
    file: Type.Object({ filename: Type.String(), url: Type.String(), content: Type.String() }),
  }),
});

const SiteParams = Type.Object({ siteId: Type.String({ format: 'uuid' }) }, { additionalProperties: false });
const strict = { additionalProperties: false } as const;

export const siteRoutes: FastifyPluginAsyncTypebox<{ sites: SiteService }> = async (app, { sites }) => {
  app.addHook('preHandler', requireAuth);
  const owner = (req: FastifyRequest) => req.auth!.userId;

  app.get('/', { schema: { response: { 200: Type.Object({ sites: Type.Array(Site) }) } } }, async (req) => ({
    sites: await sites.list(owner(req)),
  }));

  app.post(
    '/',
    {
      schema: {
        body: Type.Object({ domain: Type.String({ minLength: 1, maxLength: 2048 }) }, strict),
        response: { 201: Type.Object({ site: Site }) },
      },
    },
    async (req, reply) => reply.code(201).send({ site: await sites.create(owner(req), req.body.domain, requestContext(req)) }),
  );

  app.get('/:siteId', { schema: { params: SiteParams, response: { 200: Type.Object({ site: Site }) } } }, async (req) => ({
    site: await sites.get(owner(req), req.params.siteId),
  }));

  app.post(
    '/:siteId/verify',
    {
      // Each attempt makes a DNS query or an HTTP request to the site, so keep it modest.
      config: {
        rateLimit: { max: 10, timeWindow: '1 minute', keyGenerator: (req: FastifyRequest) => `verify:${req.auth?.userId ?? req.ip}` },
      },
      schema: {
        params: SiteParams,
        body: Type.Object({ method: Method }, strict),
        response: { 200: Type.Object({ verified: Type.Boolean(), message: Type.String(), site: Site }) },
      },
    },
    async (req) => sites.verify(owner(req), req.params.siteId, req.body.method, requestContext(req)),
  );

  app.patch(
    '/:siteId',
    {
      schema: {
        params: SiteParams,
        body: Type.Object({ weeklyScan: Type.Boolean() }, strict),
        response: { 200: Type.Object({ site: Site }) },
      },
    },
    async (req) => ({ site: await sites.setWeeklyScan(owner(req), req.params.siteId, req.body.weeklyScan, requestContext(req)) }),
  );

  app.delete('/:siteId', { schema: { params: SiteParams, response: { 204: Type.Null() } } }, async (req, reply) => {
    await sites.remove(owner(req), req.params.siteId, requestContext(req));
    return reply.code(204).send(null);
  });
};
