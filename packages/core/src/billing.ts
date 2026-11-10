import { randomBytes } from 'node:crypto';
import { eq, sql } from 'drizzle-orm';
import { sites, subscriptions, type Database } from '@shc/db';
import { effectivePlan, type Plan } from '@shc/shared';
import { audit } from './audit';

export async function planFor(db: Database, userId: string): Promise<Plan> {
  const [sub] = await db.select({ plan: subscriptions.plan, status: subscriptions.status }).from(subscriptions).where(eq(subscriptions.userId, userId)).limit(1);
  return effectivePlan(sub?.plan, sub?.status);
}

export type CheckoutResult = { kind: 'activated' } | { kind: 'redirect'; url: string };

/**
 * The boundary to a real payment provider (Stripe, Paddle, …). Only the stub exists in
 * the MVP; a real provider would return a hosted-checkout URL and confirm by webhook.
 */
export interface PaymentProvider {
  readonly name: 'stub' | 'none';
  startCheckout(input: { userId: string; plan: 'pro'; ip?: string | null }): Promise<CheckoutResult>;
  cancel(input: { userId: string; ip?: string | null }): Promise<void>;
}

export class PaymentsUnavailableError extends Error {
  constructor() {
    super('Upgrades are not available yet.');
    this.name = 'PaymentsUnavailableError';
  }
}

/** Development only (refused in production by config): upgrades and cancels instantly. */
export class StubPaymentProvider implements PaymentProvider {
  readonly name = 'stub' as const;

  constructor(private readonly db: Database) {}

  async startCheckout({ userId, ip }: { userId: string; plan: 'pro'; ip?: string | null }): Promise<CheckoutResult> {
    await this.db
      .update(subscriptions)
      .set({
        plan: 'pro',
        status: 'active',
        provider: 'stub',
        providerRef: `stub_${randomBytes(8).toString('hex')}`,
        currentPeriodEnd: sql`now() + interval '30 days'`,
        updatedAt: sql`now()`,
      })
      .where(eq(subscriptions.userId, userId));
    await audit(this.db, { event: 'plan_changed', userId, ip, meta: { plan: 'pro', provider: 'stub' } });
    return { kind: 'activated' };
  }

  async cancel({ userId, ip }: { userId: string; ip?: string | null }): Promise<void> {
    await this.db.transaction(async (tx) => {
      await tx
        .update(subscriptions)
        .set({ plan: 'free', status: 'active', providerRef: null, currentPeriodEnd: null, updatedAt: sql`now()` })
        .where(eq(subscriptions.userId, userId));
      // Weekly scans are a Pro feature.
      await tx.update(sites).set({ weeklyScan: false, nextScanAt: null }).where(eq(sites.ownerId, userId));
    });
    await audit(this.db, { event: 'plan_changed', userId, ip, meta: { plan: 'free', provider: 'stub' } });
  }
}

export class NoPaymentProvider implements PaymentProvider {
  readonly name = 'none' as const;
  async startCheckout(): Promise<CheckoutResult> {
    throw new PaymentsUnavailableError();
  }
  async cancel(): Promise<void> {
    throw new PaymentsUnavailableError();
  }
}
