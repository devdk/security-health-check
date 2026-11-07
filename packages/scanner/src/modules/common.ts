import type { PoliteResponse } from '../polite-client';
import type { ScanContext, ScanTarget } from '../types';

/** One shared fetch of the home page per scan (the client caches identical GETs). */
export const HOMEPAGE_OPTIONS = { followRedirects: true, maxBytes: 512 * 1024 } as const;
export const homepage = (target: ScanTarget, ctx: ScanContext): Promise<PoliteResponse> =>
  ctx.http.get(`${target.baseUrl}/`, HOMEPAGE_OPTIONS);

/** Shared fetch of the login page (admin-exposure and headers both read it). */
export const LOGIN_OPTIONS = { followRedirects: false, maxBytes: 64 * 1024 } as const;
export const loginPage = (target: ScanTarget, ctx: ScanContext): Promise<PoliteResponse> =>
  ctx.http.get(`${target.baseUrl}/wp-login.php`, LOGIN_OPTIONS);

export function header(res: PoliteResponse, name: string): string | undefined {
  const v = res.headers[name.toLowerCase()];
  return Array.isArray(v) ? v.join(', ') : v;
}

export function headerList(res: PoliteResponse, name: string): string[] {
  const v = res.headers[name.toLowerCase()];
  return v === undefined ? [] : Array.isArray(v) ? v : [v];
}

export const text = (res: PoliteResponse) => res.body.toString('utf8');

/** Show enough of a username to recognise it without storing it whole. */
export function mask(value: string): string {
  if (value.length <= 2) return '*'.repeat(value.length);
  return `${value[0]}${'*'.repeat(Math.min(value.length - 2, 6))}${value[value.length - 1]}`;
}
