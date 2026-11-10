import type { FastifyPluginAsyncTypebox } from '@fastify/type-provider-typebox';
import { eq } from 'drizzle-orm';
import { Type, type TSchema } from 'typebox';
import { PaymentsUnavailableError, type PaymentProvider } from '@shc/core';
import { subscriptions, type Database } from '@shc/db';
import { effectivePlan } from '@shc/shared';
import { HttpError } from '../lib/errors';
import { requestContext } from '../lib/request-context';
import { requireAuth } from '../plugins/session';

const Nullable = <T extends TSchema>(s: T) => Type.Union([s, Type.Null()]);
const Billing = Type.Object({
  plan: Type.Union([Type.Literal('free'), Type.Literal('pro')]),
  status: Type.String(),
  provider: Type.String(),
  currentPeriodEnd: Nullable(Type.String()),
  upgradesAvailable: Type.Boolean(),
  testMode: Type.Boolean(),
});

/** Mounted under /api/billing. Payments go through the PaymentProvider interface (a stub in the MVP). */
export const billingRoutes: FastifyPluginAsyncTypebox<{ db: Database; payments: PaymentProvider }> = async (app, { db, payments }) => {
  app.addHook('preHandler', requireAuth);

  const current = async (userId: string) => {
    const [sub] = await db.select().from(subscriptions).where(eq(subscriptions.userId, userId)).limit(1);
    return {
      plan: effectivePlan(sub?.plan, sub?.status),
      status: sub?.status ?? 'active',
      provider: sub?.provider ?? 'stub',
      currentPeriodEnd: sub?.currentPeriodEnd?.toISOString() ?? null,
      upgradesAvailable: payments.name !== 'none',
      testMode: payments.name === 'stub',
    };
  };
  const unavailable = (err: unknown) => {
    if (err instanceof PaymentsUnavailableError) throw new HttpError(503, 'payments_unavailable', err.message);
    throw err;
  };

  app.get('/', { schema: { response: { 200: Type.Object({ billing: Billing }) } } }, async (req) => ({ billing: await current(req.auth!.userId) }));

  app.post(
    '/upgrade',
    { schema: { body: Type.Object({ plan: Type.Literal('pro') }, { additionalProperties: false }), response: { 200: Type.Object({ billing: Billing, redirectUrl: Nullable(Type.String()) }) } } },
    async (req) => {
      const result = await payments.startCheckout({ userId: req.auth!.userId, plan: req.body.plan, ip: requestContext(req).ip }).catch(unavailable);
      return { billing: await current(req.auth!.userId), redirectUrl: result.kind === 'redirect' ? result.url : null };
    },
  );

  app.post('/cancel', { schema: { response: { 200: Type.Object({ billing: Billing }) } } }, async (req) => {
    await payments.cancel({ userId: req.auth!.userId, ip: requestContext(req).ip }).catch(unavailable);
    return { billing: await current(req.auth!.userId) };
  });
};
