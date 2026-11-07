import { EXPOSURES, type ExposureId } from '@shc/ontology';
import type { CheckModule, Finding } from '../types';
import { header } from './common';

type Matcher = (body: Buffer, contentType: string) => string | null;

const asText = (b: Buffer) => b.toString('utf8');
const looksLikeHtml = (s: string) => /<(?:!doctype|html|head|body)\b/i.test(s);

const matchers = {
  wpConfig: ((b) => (/define\s*\(\s*['"]DB_(?:NAME|USER|PASSWORD|HOST)['"]/.test(asText(b)) ? 'contains WordPress database settings' : null)) as Matcher,
  env: ((b) => {
    const s = asText(b);
    return !looksLikeHtml(s) && (s.match(/^[A-Z][A-Z0-9_]{1,60}=/gm)?.length ?? 0) >= 2 ? 'contains environment variable assignments' : null;
  }) as Matcher,
  gitHead: ((b) => (/^ref: refs\/heads\/\S+\s*$/m.test(asText(b)) || /^[0-9a-f]{40}\s*$/.test(asText(b)) ? 'is a Git HEAD file' : null)) as Matcher,
  sql: ((b) => {
    const s = asText(b);
    return !looksLikeHtml(s) && /(CREATE TABLE|INSERT INTO|-- (?:MySQL|MariaDB) dump|-- phpMyAdmin SQL Dump)/i.test(s) ? 'contains SQL database statements' : null;
  }) as Matcher,
  archive: ((b) => {
    if (b.length >= 4 && b[0] === 0x50 && b[1] === 0x4b && b[2] === 0x03 && b[3] === 0x04) return 'is a ZIP archive';
    if (b.length >= 2 && b[0] === 0x1f && b[1] === 0x8b) return 'is a gzip archive';
    return null;
  }) as Matcher,
  debugLog: ((b) => {
    const s = asText(b);
    return !looksLikeHtml(s) && (/PHP (?:Warning|Notice|Fatal error|Deprecated|Parse error):/.test(s) || /^\[\d{2}-[A-Z][a-z]{2}-\d{4} \d{2}:\d{2}:\d{2}/m.test(s))
      ? 'contains PHP error log entries'
      : null;
  }) as Matcher,
  phpinfo: ((b) => (/<title>\s*phpinfo\(\)\s*<\/title>/i.test(asText(b)) || (/PHP Version/.test(asText(b)) && /php\.ini/i.test(asText(b))) ? 'shows the full PHP configuration' : null)) as Matcher,
};

interface Probe {
  path: string;
  concept: ExposureId;
  match: Matcher;
  /** HTML responses are normally "soft 404" pages; only phpinfo is legitimately HTML. */
  htmlAllowed?: boolean;
}

export function probesFor(domain: string): Probe[] {
  const cfg = (path: string): Probe => ({ path, concept: 'exposure/config-backup-exposed', match: matchers.wpConfig });
  const sql = (path: string): Probe => ({ path, concept: 'exposure/database-dump-exposed', match: matchers.sql });
  const zip = (path: string): Probe => ({ path, concept: 'exposure/site-archive-exposed', match: matchers.archive });
  return [
    ...['/wp-config.php.bak', '/wp-config.php.old', '/wp-config.php.orig', '/wp-config.php.save', '/wp-config.php~', '/wp-config.php.txt', '/wp-config.bak', '/wp-config.old', '/wp-config.txt', '/.wp-config.php.swp', '/wp-config.php.swp'].map(cfg),
    { path: '/.env', concept: 'exposure/env-file-exposed', match: matchers.env },
    { path: '/.env.backup', concept: 'exposure/env-file-exposed', match: matchers.env },
    { path: '/.git/HEAD', concept: 'exposure/git-repository-exposed', match: matchers.gitHead },
    ...['/backup.sql', '/database.sql', '/db.sql', '/dump.sql', '/wordpress.sql', '/wp.sql', `/${domain}.sql`].map(sql),
    ...['/backup.zip', '/site.zip', '/wordpress.zip', '/www.zip', '/public_html.zip', `/${domain}.zip`, '/backup.tar.gz'].map(zip),
    { path: '/wp-content/debug.log', concept: 'exposure/debug-log-exposed', match: matchers.debugLog },
    { path: '/debug.log', concept: 'exposure/debug-log-exposed', match: matchers.debugLog },
    ...['/phpinfo.php', '/info.php', '/php_info.php', '/test.php'].map((path): Probe => ({ path, concept: 'exposure/phpinfo-exposed', match: matchers.phpinfo, htmlAllowed: true })),
  ];
}

/**
 * Looks for sensitive files left in the web root. HEAD first; a small GET (4 KB) only when
 * the HEAD suggests the file exists, and the body must match the file type, which rules
 * out "soft 404" pages. Evidence never includes file contents, only what kind of file
 * it is, because these files contain secrets.
 */
export const exposedFiles: CheckModule = {
  id: 'exposed-files',
  title: 'Exposed sensitive files',
  stage: 1,

  async run(target, ctx) {
    const findings: Finding[] = [];
    await Promise.all(
      probesFor(target.domain.replace(/^www\./, '')).map(async (probe) => {
        const url = `${target.baseUrl}${probe.path}`;
        const head = await ctx.http.head(url);
        const headAllowed = head.status !== 405 && head.status !== 501;
        if (headAllowed && head.status !== 200) return;
        if (headAllowed && !probe.htmlAllowed && /text\/html/i.test(header(head, 'content-type') ?? '')) return;

        const res = await ctx.http.get(url, { maxBytes: 4096 });
        if (res.status !== 200) return;
        const contentType = header(res, 'content-type') ?? '';
        const reason = probe.match(res.body, contentType);
        if (!reason) return;
        findings.push({
          checkId: `exposed-files.${probe.concept.replace('exposure/', '')}`,
          conceptId: probe.concept,
          severity: EXPOSURES[probe.concept].defaultSeverity,
          title: `${probe.path} is publicly downloadable and ${reason}`,
          confidence: 'confirmed',
          evidence: { url, status: res.status, detail: { matched: reason, contentType, size: header(res, 'content-length') ?? null } },
        });
      }),
    );
    return findings;
  },
};
