import type { FastifyPluginAsyncTypebox } from '@fastify/type-provider-typebox';
import { sql } from 'drizzle-orm';
import { Type } from 'typebox';
import type { Redis } from 'ioredis';
import type { Database } from '@shc/db';

export const healthRoutes: FastifyPluginAsyncTypebox<{ db: Database; redis: Redis }> = async (app, { db, redis }) => {
  app.get(
    '/health',
    {
      config: { rateLimit: false },
      schema: { response: { 200: Type.Object({ status: Type.Literal('ok') }), 503: Type.Object({ status: Type.Literal('unavailable') }) } },
    },
    async (req, reply) => {
      try {
        await db.execute(sql`select 1`);
        await redis.ping();
        return { status: 'ok' as const };
      } catch (err) {
        req.log.warn({ err }, 'health check failed');
        return reply.code(503).send({ status: 'unavailable' as const });
      }
    },
  );
};
