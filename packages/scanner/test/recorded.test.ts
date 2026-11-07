import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { runScan } from '../src/engine';
import { noRateLimit } from '../src/rate-limit';
import { FixtureFetcher, loadFixture, memoryVulns } from '../src/testing';

// Genuine responses recorded from the local test WordPress (docker compose --profile testwp),
// re-recordable with `npm run record-fixtures -w @shc/scanner`.
const { routes } = loadFixture(path.join(import.meta.dirname, 'fixtures', 'testwp-recorded'));

describe('scan replayed from a real WordPress install', () => {
  it('identifies core, the outdated plugin and the theme, and flags the known vulnerability', async () => {
    const vulns = memoryVulns({
      'plugin:contact-form-7': [
        {
          source: 'nvd',
          sourceId: 'CVE-2020-35489',
          title: 'Unrestricted file upload',
          cveIds: ['CVE-2020-35489'],
          cvssScore: null,
          severity: 'critical',
          affected: [{ to: '5.3.1', toInclusive: true }],
          fixedIn: '5.3.2',
          references: [],
        },
      ],
    });
    const outcome = await runScan({
      domain: 'wordpress.test',
      fetcher: new FixtureFetcher(routes),
      limiter: noRateLimit,
      vulns,
      maxRequests: 150,
      timeoutMs: 10_000,
    });

    expect(outcome.baseUrl).toBe('http://wordpress.test'); // no TLS on the test site: fell back to HTTP
    const versions = Object.fromEntries(outcome.components.map((c) => [`${c.type}:${c.slug}`, `${c.version} (${c.versionConfidence})`]));
    expect(versions).toEqual({
      'core:wordpress': '6.4.2 (confirmed)',
      'plugin:contact-form-7': '5.3.1 (likely)',
      'theme:twentytwentyone': '2.0 (confirmed)',
    });
    expect(outcome.findings.map((f) => `${f.severity} ${f.conceptId}`).sort()).toEqual([
      'critical exposure/known-vulnerable-component',
      'info exposure/component-versions-disclosed',
      'low exposure/wordpress-version-disclosed',
    ]);
    expect(outcome.modules.every((m) => m.status === 'ok')).toBe(true);
  });
});
