import rateLimit from '@fastify/rate-limit';
import type { FastifyInstance, FastifyRequest } from 'fastify';
import type { Redis } from 'ioredis';
import type { Config } from '@shc/config';

/** Signed-in users are limited per account; anonymous traffic per IP. */
export function userOrIpKey(request: FastifyRequest): string {
  return request.auth ? `u:${request.auth.userId}` : `ip:${request.ip}`;
}

export async function registerRateLimit(app: FastifyInstance, config: Config, redis: Redis): Promise<void> {
  await app.register(rateLimit, {
    global: true,
    // Run after the session hook so we know who the user is.
    hook: 'preHandler',
    max: config.rateLimit.globalPerMinute,
    timeWindow: '1 minute',
    redis,
    nameSpace: 'shc:rl:',
    keyGenerator: userOrIpKey,
  });
}

/** Stricter per-IP limit for credential and email-sending endpoints. */
export function authRouteLimit(config: Config) {
  return {
    rateLimit: {
      max: config.rateLimit.authPerMinute,
      timeWindow: '1 minute',
      keyGenerator: (request: FastifyRequest) => `auth:${request.ip}`,
    },
  };
}
