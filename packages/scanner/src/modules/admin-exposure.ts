import type { CheckModule } from '../types';
import { header, loginPage, text } from './common';

/** Markers of extra login protection that are visible without trying to log in. */
const PROTECTION_MARKERS: Array<[RegExp, string]> = [
  [/g-recaptcha|grecaptcha|recaptcha\/api|h-captcha|hcaptcha\.com|cf-turnstile|challenges\.cloudflare\.com\/turnstile/i, 'CAPTCHA'],
  [/two[-_ ]?factor|2fa|wfls-|wordfence-ls|itsec-|google-authenticator|miniorange|wp-2fa|duo_web/i, 'two-factor or security plugin'],
  [/limit-login|loginizer|llar-|cerber|wp-cerber/i, 'login rate limiting'],
];

/**
 * Loads wp-login.php and /wp-admin/ like a browser would (no login attempts) and reports
 * when both are open to anyone with no visible protection. Rate limiting that only kicks
 * in after failed attempts can't be seen this way, hence "possible" confidence.
 */
export const adminExposure: CheckModule = {
  id: 'admin-exposure',
  title: 'Login and admin exposure',
  stage: 1,

  async run(target, ctx) {
    const login = await loginPage(target, ctx);
    const body = text(login);
    if (login.status !== 200 || !/name=["']loginform["']|id=["']user_login["']/i.test(body)) return [];

    const protections = PROTECTION_MARKERS.filter(([re]) => re.test(body)).map(([, label]) => label);
    if (protections.length > 0) return [];

    const admin = await ctx.http.get(`${target.baseUrl}/wp-admin/`, { followRedirects: false, maxBytes: 4096 });
    // 401/403 means wp-admin sits behind HTTP auth or an IP allow-list.
    if (admin.status === 401 || admin.status === 403) return [];

    return [
      {
        checkId: 'admin-exposure.login-open',
        conceptId: 'exposure/login-unprotected',
        severity: 'medium',
        title: 'The login page is open to everyone with no visible extra protection',
        confidence: 'possible',
        evidence: {
          url: login.url,
          status: login.status,
          detail: { wpAdminStatus: admin.status, wpAdminRedirect: header(admin, 'location') ?? null, protectionMarkersFound: [] },
        },
      },
    ];
  },
};
