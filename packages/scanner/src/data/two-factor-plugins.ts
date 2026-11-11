/**
 * WordPress.org slugs of plugins that add two-factor sign-in, checked against the
 * plugin directory API on 2026-11-11. Security suites are included when their free
 * version ships two-factor sign-in. An active plugin from this list is taken as 2FA
 * being in place, which is why the "no two-factor" finding is only "likely".
 * wordfence-login-security is closed in the directory, but sites that installed it keep it.
 */
export const TWO_FACTOR_PLUGINS: ReadonlySet<string> = new Set([
  'two-factor',
  'two-factor-authentication',
  'wp-2fa',
  'miniorange-2-factor-authentication',
  'google-authenticator',
  'duo-wordpress',
  'rublon',
  'wordfence-login-security',
  'wordfence',
  'better-wp-security',
  'all-in-one-wp-security-and-firewall',
  'wp-simple-firewall',
  'defender-security',
]);
