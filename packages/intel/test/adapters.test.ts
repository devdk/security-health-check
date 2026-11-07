import { readFileSync } from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import type { FetchJson } from '../src/http';
import { NvdAdapter, parseNvdCve } from '../src/nvd';
import { OsvAdapter } from '../src/osv';
import { parseWordfenceRecord, WordfenceAdapter } from '../src/wordfence';
import { fetchCoreStatus, fetchDirectoryVersion } from '../src/wporg';

const fixture = (name: string) => JSON.parse(readFileSync(path.join(import.meta.dirname, 'fixtures', name), 'utf8'));

/** Records calls and replays canned responses; no network. */
function fakeFetch(responses: Array<{ status: number; json: unknown }>) {
  const calls: Array<{ url: string; headers: Record<string, string> }> = [];
  const fn: FetchJson = async (url, init) => {
    calls.push({ url, headers: init?.headers ?? {} });
    const next = responses.shift();
    if (!next) throw new Error(`unexpected request ${url}`);
    return next;
  };
  return { fn, calls };
}

describe('Wordfence v3 production feed', () => {
  const feed = fixture('wordfence-production.json');

  it('turns each record into one row per affected software, with attribution kept', () => {
    const rows = Object.values(feed).flatMap(parseWordfenceRecord);
    expect(rows.map((r) => `${r.softwareType}:${r.slug}`)).toEqual(['plugin:contact-form-7', 'core:wordpress', 'plugin:example-plugin', 'theme:example-theme']);

    const cf7 = rows[0]!;
    expect(cf7).toMatchObject({
      source: 'wordfence',
      sourceId: '6a2e5d1c-1111-4b6e-9a0e-000000000001',
      cveIds: ['CVE-2020-35489'],
      cvssScore: 9.8,
      severity: 'critical',
      affected: [{ from: '*', fromInclusive: true, to: '5.3.1', toInclusive: true }],
      fixedIn: '5.3.2',
      remediation: 'Update to version 5.3.2, or a newer patched version',
      cwe: { id: 434, name: 'Unrestricted Upload of File with Dangerous Type' },
      recordUrl: 'https://www.wordfence.com/threat-intel/vulnerabilities/id/6a2e5d1c-1111-4b6e-9a0e-000000000001',
      informational: false,
    });
    expect(Object.keys(cf7.copyrights!.holders)).toEqual(['defiant', 'mitre']);
    expect(cf7.copyrights!.holders.mitre!.notice).toMatch(/MITRE/);
    expect(cf7.copyrights!.holders.defiant!.licenseUrl).toBe('https://www.wordfence.com/wti-community-edition-terms-and-conditions/');
    expect(cf7.publishedAt?.toISOString()).toBe('2020-12-17T00:00:00.000Z');
  });

  it('keeps exclusive bounds, informational status and the lowest patched version', () => {
    const rows = Object.values(feed).flatMap(parseWordfenceRecord);
    expect(rows[1]!.affected).toEqual([{ from: '6.4', fromInclusive: true, to: '6.4.3', toInclusive: false }]);
    const theme = rows[3]!;
    expect(theme).toMatchObject({ informational: true, severity: 'info', fixedIn: '2.0.1', copyrights: null });
  });

  it('is switched off until an API key is configured', async () => {
    const adapter = new WordfenceAdapter({});
    expect(adapter.disabledReason()).toMatch(/WORDFENCE_API_KEY/);
    await expect(adapter.fetch()).rejects.toThrow(/WORDFENCE_API_KEY/);
  });

  it('authenticates with a Bearer token', async () => {
    const { fn, calls } = fakeFetch([{ status: 200, json: feed }]);
    const rows = await new WordfenceAdapter({ apiKey: 'test-key-0123456789abcdef', fetchJson: fn }).fetch();
    expect(rows).toHaveLength(4);
    expect(calls[0]!.url).toBe('https://www.wordfence.com/api/intelligence/v3/vulnerabilities/production');
    expect(calls[0]!.headers.authorization).toBe('Bearer test-key-0123456789abcdef');
  });

  it.each([
    [401, /rejected the API key/],
    [429, /rate limit/],
    [500, /HTTP 500/],
  ])('reports HTTP %i clearly', async (status, message) => {
    const { fn } = fakeFetch([{ status, json: null }]);
    await expect(new WordfenceAdapter({ apiKey: 'k'.repeat(20), fetchJson: fn }).fetch()).rejects.toThrow(message);
  });
});

describe('NVD CVE API (PHP runtime)', () => {
  const page = fixture('nvd-php.json');

  it('extracts PHP version ranges and scores, skipping rejected and non-PHP records', () => {
    const rows = page.vulnerabilities.map(parseNvdCve).filter(Boolean);
    expect(rows.map((r: { sourceId: string }) => r.sourceId)).toEqual(['CVE-2024-4577', 'CVE-2023-0001']);
    expect(rows[0]).toMatchObject({
      softwareType: 'php',
      slug: 'php',
      cvssScore: 9.8,
      severity: 'critical',
      affected: [
        { from: '8.1.0', fromInclusive: true, to: '8.1.29', toInclusive: false },
        { from: '8.2.0', fromInclusive: true, to: '8.2.20', toInclusive: false },
      ],
      cwe: { id: 78 },
      recordUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2024-4577',
    });
    expect(rows[0].title).toMatch(/^In PHP versions 8\.1\.\*/);
    expect(rows[1]).toMatchObject({ affected: [{ from: '7.4.33', to: '7.4.33' }], severity: 'medium' });
  });

  it('pages through results politely and sends the key when configured', async () => {
    const first = { ...page, totalResults: 6, vulnerabilities: page.vulnerabilities.slice(0, 2) };
    const second = { ...page, totalResults: 6, startIndex: 2, vulnerabilities: page.vulnerabilities.slice(2) };
    const { fn, calls } = fakeFetch([
      { status: 200, json: first },
      { status: 200, json: second },
      { status: 200, json: { ...page, totalResults: 6, startIndex: 4, vulnerabilities: [] } },
    ]);
    const rows = await new NvdAdapter({ apiKey: 'nvd-key-0123456789', fetchJson: fn, pauseMs: 0 }).fetch();
    expect(rows).toHaveLength(2);
    expect(calls.map((c) => new URL(c.url).searchParams.get('startIndex'))).toEqual(['0', '2', '4']);
    expect(new URL(calls[0]!.url).searchParams.get('virtualMatchString')).toBe('cpe:2.3:a:php:php');
    expect(calls[0]!.headers.apiKey).toBe('nvd-key-0123456789');
  });

  it('asks only for recent changes on later runs, within NVD’s 120-day window', async () => {
    const { fn, calls } = fakeFetch([
      { status: 200, json: { ...page, vulnerabilities: [], totalResults: 0 } },
      { status: 200, json: { ...page, vulnerabilities: [], totalResults: 0 } },
    ]);
    const adapter = new NvdAdapter({ fetchJson: fn, pauseMs: 0 });
    await adapter.fetch({ since: new Date(Date.now() - 2 * 86_400_000) });
    await adapter.fetch({ since: new Date(Date.now() - 400 * 86_400_000) });
    expect(new URL(calls[0]!.url).searchParams.get('lastModStartDate')).toBeTruthy();
    expect(new URL(calls[1]!.url).searchParams.get('lastModStartDate')).toBeNull(); // too old: full refresh
  });
});

describe('OSV slot', () => {
  it('is reserved but switched off', async () => {
    const osv = new OsvAdapter();
    expect(osv.disabledReason()).toMatch(/no WordPress/);
    expect(await osv.fetch()).toEqual([]);
  });
});

describe('WordPress.org', () => {
  it('reads core release status', async () => {
    const { fn } = fakeFetch([{ status: 200, json: { '6.4.2': 'insecure', '6.9.11': 'outdated', '7.1.4': 'latest', junk: 'nope' } }]);
    expect(await fetchCoreStatus(fn)).toEqual({ latest: '7.1.4', versions: { '6.4.2': 'insecure', '6.9.11': 'outdated', '7.1.4': 'latest' } });
  });

  it('looks up plugin versions and recognises premium plugins', async () => {
    const { fn, calls } = fakeFetch([
      { status: 200, json: { slug: 'contact-form-7', version: '6.1.2' } },
      { status: 404, json: { error: 'Plugin not found.' } },
    ]);
    expect(await fetchDirectoryVersion('plugin', 'contact-form-7', fn)).toEqual({ found: true, version: '6.1.2' });
    expect(await fetchDirectoryVersion('plugin', 'premium-thing', fn)).toEqual({ found: false, version: null });
    expect(calls[0]!.url).toContain('request%5Bslug%5D=contact-form-7');
    expect(await fetchDirectoryVersion('plugin', '../etc', fn)).toEqual({ found: false, version: null });
    expect(calls).toHaveLength(2);
  });
});
