import type { FastifyRequest } from 'fastify';
import type { RequestContext } from '../services/auth-service';

export function requestContext(req: FastifyRequest): RequestContext {
  const ua = req.headers['user-agent'];
  return { ip: req.ip, userAgent: typeof ua === 'string' ? ua : undefined };
}
