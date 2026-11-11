import { eq } from 'drizzle-orm';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { auditEvents, findings, pluginKeys, pluginReports, scans, serviceRequests, siteComponents, sites, subscriptions } from '@shc/db';
import type { PdfRenderer } from '../src/lib/pdf';
import { createTestContext, get, post, resetState, signedInUser, type TestContext } from './helpers';

/** Captures the HTML instead of running Chromium. */
class FakePdf implements PdfRenderer {
  html: string | null = null;
  async render(html: string): Promise<Buffer> {
    this.html = html;
    return Buffer.from('%PDF-1.7 fake');
  }
}

const pdf = new FakePdf();
let ctx: TestContext;
let alice: string;
let siteId: string;

beforeAll(async () => {
  ctx = await createTestContext({ pdf });
});
afterAll(async () => {
  await ctx.close();
});
beforeEach(async () => {
  await resetState(ctx);
  pdf.html = null;
  alice = await signedInUser(ctx, 'alice@example.com');
  siteId = (await post(ctx, '/api/sites', { domain: 'example.com' }, alice)).json().site.id;
  await ctx.db.update(sites).set({ verifiedAt: new Date(), verificationMethod: 'dns_txt' }).where(eq(sites.id, siteId));
});

const makePro = async () => {
  const res = await post(ctx, '/api/billing/upgrade', { plan: 'pro' }, alice);
  expect(res.statusCode).toBe(200);
};

/** A finished scan with one finding visible to free users, one locked, one compromise indicator. */
async function finishedScan(createdAt = new Date()) {
  const [scan] = await ctx.db
    .insert(scans)
    .values({ siteId, requestedBy: null, kind: 'external', trigger: 'manual', status: 'completed', createdAt, finishedAt: createdAt, score: 12, grade: 'F', requestCount: 40, baseUrl: 'https://example.com' })
    .returning();
  const base = { scanId: scan!.id, checkId: 'x.y', fixSteps: 'stored', references: [] };
  const rows = await ctx.db
    .insert(findings)
    .values([
      { ...base, conceptId: 'exposure/php-in-uploads', severity: 'critical', title: 'PHP files in uploads: shell.php', explanation: 'COMPROMISE-EXPLANATION', indicatesCompromise: true, sortOrder: 0, evidence: { url: 'https://example.com/wp-content/uploads/shell.php' } },
      { ...base, conceptId: 'exposure/config-backup-exposed', severity: 'critical', title: 'LOCKED-TITLE wp-config.php.bak', explanation: 'LOCKED-EXPLANATION', sortOrder: 1, evidence: { url: 'https://example.com/LOCKED-URL' } },
      { ...base, conceptId: 'exposure/xmlrpc-enabled', severity: 'medium', title: 'VISIBLE-TITLE xmlrpc', explanation: 'VISIBLE-EXPLANATION', visibleInFree: true, sortOrder: 2, evidence: {} },
    ])
    .returning();
  return { scanId: scan!.id, findingIds: rows.map((r) => r.id) };
}

describe('report visibility (decided by the API, not the browser)', () => {
  it('gives free users the score, counts, the chosen findings and compromise warnings, and nothing else', async () => {
    const { scanId } = await finishedScan();
    const res = await get(ctx, `/api/scans/${scanId}/report`, alice);
    expect(res.statusCode).toBe(200);
    const report = res.json().report;
    expect(report).toMatchObject({ plan: 'free', score: 12, grade: 'F', counts: { critical: 2, medium: 1 }, compromiseSuspected: true, lockedCount: 1 });

    const [compromise, locked, visible] = report.findings;
    expect(compromise).toMatchObject({ locked: false, indicatesCompromise: true, fix: null, fixLocked: true, explanation: 'COMPROMISE-EXPLANATION' });
    expect(locked).toEqual({ id: expect.any(String), locked: true, severity: 'critical', category: 'Publicly served files' });
    expect(visible).toMatchObject({ locked: false, title: 'VISIBLE-TITLE xmlrpc', fixLocked: false });
    expect(visible.fix.length).toBeGreaterThan(0);

    // The raw response body must not carry anything from the locked finding.
    for (const secret of ['LOCKED-TITLE', 'LOCKED-EXPLANATION', 'LOCKED-URL']) expect(res.body).not.toContain(secret);
    expect(report.features).toEqual({ pdf: false, history: false, fixRequests: false, weeklyScans: false });
  });

  it('gives Pro users everything, including fix guides for compromise findings', async () => {
    const { scanId } = await finishedScan();
    await makePro();
    const report = (await get(ctx, `/api/scans/${scanId}/report`, alice)).json().report;
    expect(report.plan).toBe('pro');
    expect(report.lockedCount).toBe(0);
    expect(report.findings.every((f: { locked: boolean; fix: unknown[] }) => !f.locked && f.fix.length > 0)).toBe(true);
  });

  it('keeps older reports for Pro (scan history)', async () => {
    const old = await finishedScan(new Date(Date.now() - 7 * 86_400_000));
    await finishedScan();
    const free = await get(ctx, `/api/scans/${old.scanId}/report`, alice);
    expect(free.statusCode).toBe(403);
    expect(free.json().error).toBe('upgrade_required');
    const list = (await get(ctx, `/api/sites/${siteId}/scans`, alice)).json();
    expect(list.scans).toHaveLength(1);
    expect(list.historyLimited).toBe(true);

    await makePro();
    expect((await get(ctx, `/api/scans/${old.scanId}/report`, alice)).statusCode).toBe(200);
    expect((await get(ctx, `/api/sites/${siteId}/scans`, alice)).json()).toMatchObject({ historyLimited: false, scans: [{}, {}] });
  });

  it("hides other users' reports", async () => {
    const { scanId } = await finishedScan();
    const bob = await signedInUser(ctx, 'bob@example.com');
    expect((await get(ctx, `/api/scans/${scanId}/report`, bob)).statusCode).toBe(404);
  });

  it('waits for the scan to finish', async () => {
    const [scan] = await ctx.db.insert(scans).values({ siteId, kind: 'external', trigger: 'manual', status: 'running' }).returning();
    expect((await get(ctx, `/api/scans/${scan!.id}/report`, alice)).json().error).toBe('scan_not_finished');
  });
});

describe('merged inside and outside report', () => {
  const HOUR = 3_600_000;
  const anchorTime = new Date(Date.now() - 2 * HOUR);

  /** A completed scan holding one finding about Contact Form 7, as the given view saw it. */
  async function scanWithCf7(kind: 'external' | 'inside', finishedAt: Date) {
    const [scan] = await ctx.db
      .insert(scans)
      .values({ siteId, kind, trigger: kind === 'inside' ? 'plugin' : 'manual', status: 'completed', createdAt: finishedAt, finishedAt, score: 70, grade: 'C', requestCount: kind === 'inside' ? 0 : 40, baseUrl: 'https://example.com' })
      .returning();
    const [cf7] = await ctx.db
      .insert(siteComponents)
      .values({ scanId: scan!.id, siteId, softwareType: 'plugin', slug: 'contact-form-7', version: kind === 'inside' ? '5.9' : '5.3.1', versionConfidence: kind === 'inside' ? 'confirmed' : 'likely', active: kind === 'inside' ? false : null })
      .returning();
    const [finding] = await ctx.db
      .insert(findings)
      .values(
        kind === 'inside'
          ? { scanId: scan!.id, checkId: 'plugin.inactive-component-installed', conceptId: 'exposure/inactive-component-installed', componentId: cf7!.id, severity: 'low', title: 'INSIDE-UNUSED', explanation: 'x', fixSteps: 'x' }
          : { scanId: scan!.id, checkId: 'vuln-match.wordfence', conceptId: 'exposure/known-vulnerable-component', componentId: cf7!.id, severity: 'critical', title: 'OUTSIDE-GUESS', explanation: 'x', fixSteps: 'x' },
      )
      .returning();
    if (kind === 'inside') {
      const [key] = await ctx.db.insert(pluginKeys).values({ siteId, keyHash: 'h', expiresAt: new Date(Date.now() + 86_400_000) }).returning();
      await ctx.db.insert(pluginReports).values({ siteId, pluginKeyId: key!.id, scanId: scan!.id, signedAt: finishedAt, nonce: `nonce-${scan!.id}`, pluginVersion: '0.1.0', payload: {}, payloadSha256: 'x' });
    }
    return { scanId: scan!.id, findingId: finding!.id };
  }
  const report = async (scanId: string) => (await get(ctx, `/api/scans/${scanId}/report`, alice)).json().report;

  it('merges each scan with the newest scan of the other kind that finished before it', async () => {
    await makePro();
    const paired = await scanWithCf7('inside', new Date(anchorTime.getTime() - 48 * HOUR));
    const outside = await scanWithCf7('external', anchorTime);
    const later = await scanWithCf7('inside', new Date(anchorTime.getTime() + HOUR));

    const view = await report(outside.scanId);
    expect(view).toMatchObject({
      kind: 'external',
      score: 70,
      outside: { scanId: outside.scanId, baseUrl: 'https://example.com', requestCount: 40 },
      inside: { scanId: paired.scanId, pluginVersion: '0.1.0' },
    });
    // The inside view lists Contact Form 7, so the outside vulnerability guess is dropped.
    expect(view.findings.map((f: { id: string; source: string }) => [f.id, f.source])).toEqual([[paired.findingId, 'inside']]);
    expect(view.components).toEqual([{ type: 'plugin', slug: 'contact-form-7', name: null, version: '5.9', versionConfidence: 'confirmed', active: false }]);

    expect((await report(later.scanId)).outside.scanId).toBe(outside.scanId);
  });

  it('ignores a counterpart that finished more than 30 days earlier', async () => {
    await makePro();
    await scanWithCf7('inside', new Date(anchorTime.getTime() - 31 * 24 * HOUR));
    const outside = await scanWithCf7('external', anchorTime);
    const view = await report(outside.scanId);
    expect(view).toMatchObject({ inside: null, findings: [{ id: outside.findingId, source: 'outside', title: 'OUTSIDE-GUESS' }] });
  });

  it('shows free users the newest scan of any kind, with inside findings locked', async () => {
    const outside = await scanWithCf7('external', anchorTime);
    const inside = await scanWithCf7('inside', new Date(anchorTime.getTime() + HOUR));
    expect((await get(ctx, `/api/scans/${outside.scanId}/report`, alice)).json().error).toBe('upgrade_required');
    const view = await report(inside.scanId);
    expect(view.findings).toEqual([{ id: inside.findingId, locked: true, severity: 'low', category: 'Plugin' }]);
  });
});

describe('PDF export', () => {
  it('is a Pro feature', async () => {
    const { scanId } = await finishedScan();
    const res = await get(ctx, `/api/scans/${scanId}/report.pdf`, alice);
    expect(res.statusCode).toBe(403);
    expect(pdf.html).toBeNull();
  });

  it('renders the full report to PDF for Pro users', async () => {
    const { scanId } = await finishedScan();
    await makePro();
    const res = await get(ctx, `/api/scans/${scanId}/report.pdf`, alice);
    expect(res.statusCode).toBe(200);
    expect(res.headers['content-type']).toBe('application/pdf');
    expect(res.headers['content-disposition']).toMatch(/^attachment; filename="security-report-example\.com-\d{4}-\d{2}-\d{2}\.pdf"$/);
    expect(res.rawPayload.subarray(0, 5).toString()).toBe('%PDF-');
    expect(pdf.html).toContain('LOCKED-TITLE');
    expect(pdf.html).toContain('How to fix it');
    expect((await ctx.db.select().from(auditEvents)).map((e) => e.event)).toContain('report_exported');
  });
});

describe('request a fix', () => {
  it('is Pro only, records one open request per finding, and shows up in the report', async () => {
    const { scanId, findingIds } = await finishedScan();
    const target = findingIds[1]!;
    expect((await post(ctx, `/api/findings/${target}/fix-request`, { message: '' }, alice)).statusCode).toBe(403);

    await makePro();
    const first = await post(ctx, `/api/findings/${target}/fix-request`, { message: 'Please help with this backup file' }, alice);
    expect(first.statusCode).toBe(200);
    expect(first.json()).toMatchObject({ created: true, request: { status: 'open' } });
    const again = await post(ctx, `/api/findings/${target}/fix-request`, { message: 'again' }, alice);
    expect(again.json().created).toBe(false);
    expect(await ctx.db.select().from(serviceRequests)).toHaveLength(1);

    const report = (await get(ctx, `/api/scans/${scanId}/report`, alice)).json().report;
    expect(report.findings[1].fixRequest).toMatchObject({ status: 'open' });
  });

  it("can't target another user's finding", async () => {
    const { findingIds } = await finishedScan();
    const bob = await signedInUser(ctx, 'bob@example.com');
    await post(ctx, '/api/billing/upgrade', { plan: 'pro' }, bob);
    expect((await post(ctx, `/api/findings/${findingIds[0]}/fix-request`, { message: '' }, bob)).statusCode).toBe(404);
  });
});

describe('billing (stub provider) and weekly scans', () => {
  it('upgrades and cancels instantly in test mode', async () => {
    const before = (await get(ctx, '/api/billing', alice)).json().billing;
    expect(before).toMatchObject({ plan: 'free', testMode: true, upgradesAvailable: true });
    await makePro();
    expect((await get(ctx, '/api/auth/me', alice)).json().user.plan).toBe('pro');
    const [sub] = await ctx.db.select().from(subscriptions);
    expect(sub).toMatchObject({ plan: 'pro', status: 'active', provider: 'stub' });

    const cancelled = await post(ctx, '/api/billing/cancel', {}, alice);
    expect(cancelled.json().billing.plan).toBe('free');
  });

  it('lets only Pro users switch weekly scans on, and turns them off on downgrade', async () => {
    const patch = (body: unknown) =>
      ctx.app.inject({ method: 'PATCH', url: `/api/sites/${siteId}`, payload: body as object, headers: { origin: 'http://localhost:5173', cookie: alice } });
    expect((await patch({ weeklyScan: true })).statusCode).toBe(403);

    await makePro();
    const on = await patch({ weeklyScan: true });
    expect(on.json().site).toMatchObject({ weeklyScan: true, nextScanAt: expect.any(String) });
    const days = (Date.parse(on.json().site.nextScanAt) - Date.now()) / 86_400_000;
    expect(days).toBeGreaterThan(6.9);

    await post(ctx, '/api/billing/cancel', {}, alice);
    const [site] = await ctx.db.select().from(sites).where(eq(sites.id, siteId));
    expect(site).toMatchObject({ weeklyScan: false, nextScanAt: null });
    expect((await patch({ weeklyScan: false })).statusCode).toBe(200); // switching off is always allowed
  });
});
