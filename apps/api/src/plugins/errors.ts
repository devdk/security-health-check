import type { FastifyError, FastifyInstance } from 'fastify';
import { HttpError } from '../lib/errors';

/** Consistent JSON errors; internal details and stack traces never reach the client. */
export function registerErrorHandling(app: FastifyInstance): void {
  app.setErrorHandler((error: FastifyError | HttpError, request, reply) => {
    if (error instanceof HttpError) {
      return reply.code(error.statusCode).send({ error: error.code, message: error.message });
    }
    if ('validation' in error && error.validation) {
      return reply.code(400).send({
        error: 'invalid_request',
        message: 'Request validation failed',
        details: error.validation.map((v) => ({ path: v.instancePath || v.params?.missingProperty, message: v.message })),
      });
    }
    const status = error.statusCode ?? 500;
    if (status < 500) {
      const code = status === 429 ? 'rate_limited' : status === 415 ? 'unsupported_media_type' : 'bad_request';
      return reply.code(status).send({ error: code, message: status === 429 ? 'Too many requests, slow down' : error.message });
    }
    request.log.error({ err: error }, 'unhandled error');
    return reply.code(500).send({ error: 'internal_error', message: 'Something went wrong' });
  });

  app.setNotFoundHandler((_request, reply) => {
    reply.code(404).send({ error: 'not_found', message: 'Not found' });
  });
}
