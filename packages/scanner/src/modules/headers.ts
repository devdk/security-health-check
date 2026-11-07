import type { ExposureId } from '@shc/ontology';
import type { PoliteResponse } from '../polite-client';
import type { CheckModule, Finding } from '../types';
import { header, headerList, homepage, loginPage } from './common';

const SESSION_COOKIE = /^(PHPSESSID|wordpress_logged_in_|wordpress_sec_|wp_woocommerce_session_|woocommerce_session|.*sess(ion)?(id)?$)/i;

interface CookieIssue {
  name: string;
  missing: string[];
}

function cookieIssues(responses: PoliteResponse[], https: boolean): CookieIssue[] {
  const issues = new Map<string, CookieIssue>();
  for (const res of responses) {
    for (const raw of headerList(res, 'set-cookie')) {
      const [pair, ...attrs] = raw.split(';').map((s) => s.trim());
      const name = pair?.split('=')[0] ?? '';
      if (!SESSION_COOKIE.test(name)) continue;
      const lower = attrs.map((a) => a.toLowerCase());
      const missing: string[] = [];
      if (https && !lower.includes('secure')) missing.push('Secure');
      if (!lower.includes('httponly')) missing.push('HttpOnly');
      if (!lower.some((a) => a.startsWith('samesite='))) missing.push('SameSite');
      // Cookie values are never kept: only the name and what is missing.
      if (missing.length > 0) issues.set(name, { name, missing });
    }
  }
  return [...issues.values()];
}

/**
 * Checks the browser-protection headers on the home page and the flags on session-like
 * cookies (home page and login page). Reuses responses other modules fetch.
 */
export const securityHeaders: CheckModule = {
  id: 'headers',
  title: 'Security headers and cookies',
  stage: 1,

  async run(target, ctx) {
    const home = await homepage(target, ctx);
    const https = target.baseUrl.startsWith('https:');
    const findings: Finding[] = [];
    const missing = (conceptId: ExposureId, headerName: string, title: string, severity: Finding['severity'], extra: Record<string, unknown> = {}) =>
      findings.push({
        checkId: `headers.${headerName.toLowerCase()}`,
        conceptId,
        severity,
        title,
        confidence: 'confirmed',
        evidence: { url: home.url, detail: { header: headerName, ...extra } },
      });

    const hsts = header(home, 'strict-transport-security');
    if (https && (!hsts || /max-age\s*=\s*0\b/i.test(hsts))) {
      missing('exposure/hsts-missing', 'Strict-Transport-Security', hsts ? 'HSTS is switched off (max-age=0)' : 'No Strict-Transport-Security header', 'low', hsts ? { value: hsts } : {});
    }

    const csp = header(home, 'content-security-policy');
    if (!csp) {
      const reportOnly = Boolean(header(home, 'content-security-policy-report-only'));
      missing('exposure/csp-missing', 'Content-Security-Policy', reportOnly ? 'Content Security Policy is in report-only mode' : 'No Content-Security-Policy header', 'low', { reportOnly });
    }

    const xfo = header(home, 'x-frame-options');
    if (!xfo && !/frame-ancestors/i.test(csp ?? '')) {
      missing('exposure/clickjacking-protection-missing', 'X-Frame-Options', 'No protection against being framed (X-Frame-Options or CSP frame-ancestors)', 'low');
    }

    if ((header(home, 'x-content-type-options') ?? '').toLowerCase() !== 'nosniff') {
      missing('exposure/mime-sniffing-protection-missing', 'X-Content-Type-Options', 'No X-Content-Type-Options: nosniff header', 'info');
    }
    if (!header(home, 'referrer-policy')) missing('exposure/referrer-policy-missing', 'Referrer-Policy', 'No Referrer-Policy header', 'info');
    if (!header(home, 'permissions-policy')) missing('exposure/permissions-policy-missing', 'Permissions-Policy', 'No Permissions-Policy header', 'info');

    const login = await loginPage(target, ctx).catch(() => null);
    const cookies = cookieIssues(login ? [home, login] : [home], https);
    if (cookies.length > 0) {
      findings.push({
        checkId: 'headers.cookies',
        conceptId: 'exposure/insecure-cookie-flags',
        severity: 'medium',
        title: `${cookies.length} session cookie${cookies.length === 1 ? ' is' : 's are'} missing security flags`,
        confidence: 'confirmed',
        evidence: { url: home.url, detail: { cookies } },
      });
    }
    return findings;
  },
};
