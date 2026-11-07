import { phpSupport } from '../data/php-branches';
import type { CheckModule, Finding } from '../types';
import { header, homepage } from './common';

const SERVERS = /^(Apache|nginx|LiteSpeed|openresty|Caddy|Microsoft-IIS)(?:\/([0-9][0-9.]*))?/i;

/**
 * Reads the PHP version from X-Powered-By (or a Server header that includes it) and
 * flags versions that no longer get security fixes. Also records the web server.
 * Uses the home page response other modules already fetched: no extra requests.
 */
export const phpVersion: CheckModule = {
  id: 'php-version',
  title: 'PHP version',
  stage: 1,

  async run(target, ctx) {
    const home = await homepage(target, ctx);
    const server = header(home, 'server');
    const serverMatch = server ? SERVERS.exec(server) : null;
    if (serverMatch) {
      ctx.components.add({
        type: 'web_server',
        slug: serverMatch[1]!.toLowerCase(),
        name: serverMatch[1],
        version: serverMatch[2],
        versionConfidence: serverMatch[2] ? 'confirmed' : undefined,
        sources: ['server-header'],
      });
    }

    let source: string | undefined;
    let raw: string | undefined;
    let version: string | undefined;
    for (const name of ['x-powered-by', 'server']) {
      const value = header(home, name);
      const m = value ? /PHP\/([0-9]+\.[0-9]+(?:\.[0-9]+)?)/i.exec(value) : null;
      if (m) {
        source = name;
        raw = value;
        version = m[1];
        break;
      }
    }
    if (!version) return [];

    ctx.components.add({ type: 'php', slug: 'php', name: 'PHP', version, versionConfidence: 'confirmed', sources: [`${source}-header`] });

    const findings: Finding[] = [
      {
        checkId: 'php-version.disclosed',
        conceptId: 'exposure/php-version-disclosed',
        severity: 'low',
        title: `PHP ${version} is announced in response headers`,
        confidence: 'confirmed',
        component: { type: 'php', slug: 'php' },
        evidence: { url: home.url, snippet: `${source === 'x-powered-by' ? 'X-Powered-By' : 'Server'}: ${raw}` },
      },
    ];

    const support = phpSupport(version);
    if (support.status === 'eol') {
      findings.push({
        checkId: 'php-version.unsupported',
        conceptId: 'exposure/php-unsupported',
        severity: 'high',
        title: `PHP ${support.branch} stopped receiving security fixes on ${support.securityUntil}`,
        confidence: 'confirmed',
        component: { type: 'php', slug: 'php' },
        evidence: { detail: { version, branch: support.branch, securityUntil: support.securityUntil, source: 'php.net supported versions' } },
      });
    }
    return findings;
  },
};
