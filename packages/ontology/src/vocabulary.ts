/**
 * Our own concepts: the parts of a WordPress site that can be attacked (components), the
 * protections that can be in place (controls), and the actions that fix problems
 * (remediations). Exposures, in exposures.ts, tie these together.
 */

export interface ComponentDef {
  label: string;
  description: string;
  /** Present when the component is a piece of software we track by version. */
  softwareType?: 'core' | 'plugin' | 'theme' | 'php' | 'web_server';
}

export const COMPONENTS = {
  'component/wordpress-core': { label: 'WordPress core', description: 'The WordPress application itself.', softwareType: 'core' },
  'component/plugin': { label: 'Plugin', description: 'A WordPress plugin, active or inactive.', softwareType: 'plugin' },
  'component/theme': { label: 'Theme', description: 'A WordPress theme, including parent themes.', softwareType: 'theme' },
  'component/php-runtime': { label: 'PHP runtime', description: 'The PHP version the site runs on.', softwareType: 'php' },
  'component/web-server': { label: 'Web server', description: 'The server software in front of WordPress (Apache, nginx, LiteSpeed).', softwareType: 'web_server' },
  'component/tls-endpoint': { label: 'HTTPS endpoint', description: 'The TLS certificate and protocol configuration serving the site.' },
  'component/http-response': { label: 'HTTP responses', description: 'Headers and cookies the site sends to browsers.' },
  'component/login-endpoint': { label: 'Login page', description: 'wp-login.php and the wp-admin area.' },
  'component/rest-api': { label: 'REST API', description: 'The WordPress REST API under /wp-json/.' },
  'component/xmlrpc-endpoint': { label: 'XML-RPC endpoint', description: 'The legacy remote-publishing interface at /xmlrpc.php.' },
  'component/public-files': { label: 'Publicly served files', description: 'Files and folders the web server will hand to anyone who asks.' },
  'component/user-accounts': { label: 'User accounts', description: 'WordPress users, especially administrators.' },
  'component/site-files': { label: 'Site files', description: 'PHP, configuration and uploaded files on the server.' },
} as const satisfies Record<string, ComponentDef>;
export type ComponentId = keyof typeof COMPONENTS;

export interface ControlDef {
  label: string;
  description: string;
}

export const CONTROLS = {
  'control/hsts': { label: 'HTTP Strict Transport Security', description: 'Tells browsers to only ever use HTTPS for the site.' },
  'control/csp': { label: 'Content Security Policy', description: 'Limits which scripts and resources a page may load.' },
  'control/frame-protection': { label: 'Frame protection', description: 'Stops other sites embedding yours in a frame (clickjacking).' },
  'control/two-factor-authentication': { label: 'Two-factor authentication', description: 'A second proof of identity beyond the password.' },
  'control/login-rate-limiting': { label: 'Login rate limiting', description: 'Slows or blocks repeated failed sign-in attempts.' },
  'control/web-application-firewall': { label: 'Web application firewall', description: 'Filters malicious requests before they reach WordPress.' },
  'control/automatic-updates': { label: 'Automatic updates', description: 'Installs security releases without waiting for a person.' },
  'control/offsite-backups': { label: 'Off-site backups', description: 'Backups stored away from the web server, out of public reach.' },
  'control/least-privilege': { label: 'Least privilege', description: 'Each account has only the access it needs.' },
} as const satisfies Record<string, ControlDef>;
export type ControlId = keyof typeof CONTROLS;

export interface RemediationDef {
  label: string;
  /** One or two sentences; detailed step-by-step guides are layered on in the report phase. */
  summary: string;
  effort: 'minutes' | 'hour' | 'day';
}

export const REMEDIATIONS = {
  'remediation/update-wordpress-core': {
    label: 'Update WordPress',
    summary: 'Take a backup, then update WordPress from Dashboard → Updates to the latest release.',
    effort: 'minutes',
  },
  'remediation/update-affected-component': {
    label: 'Update the affected software',
    summary: 'Update the affected plugin, theme or WordPress core to the fixed version or later. If no fix exists, deactivate and delete it until one is released.',
    effort: 'minutes',
  },
  'remediation/remove-unused-component': {
    label: 'Remove unused plugins and themes',
    summary: 'Delete plugins and themes you are not using. Deactivated code can still be reached and exploited.',
    effort: 'minutes',
  },
  'remediation/enable-auto-updates': {
    label: 'Turn on automatic updates',
    summary: 'Enable automatic updates for WordPress core, plugins and themes so security fixes install without delay.',
    effort: 'minutes',
  },
  'remediation/hide-version-info': {
    label: 'Stop advertising version numbers',
    summary: 'Remove the WordPress generator tag and version query strings. This slows attackers down; keeping software updated is the real fix.',
    effort: 'minutes',
  },
  'remediation/block-readme-files': {
    label: 'Block plugin readme files',
    summary: 'Deny web access to readme.txt and changelog files inside wp-content so plugin versions are not advertised.',
    effort: 'minutes',
  },
  'remediation/hide-php-version': {
    label: 'Hide the PHP version',
    summary: 'Set expose_php = Off in php.ini (or ask your host) so the X-Powered-By header no longer reveals the PHP version.',
    effort: 'minutes',
  },
  'remediation/upgrade-php': {
    label: 'Upgrade PHP',
    summary: 'Move the site to a PHP version that still receives security updates. Most hosts offer this in their control panel.',
    effort: 'hour',
  },
  'remediation/remove-exposed-file': {
    label: 'Remove the exposed file',
    summary: 'Delete the file from the web server or block access to it, then check your access logs to see whether anyone downloaded it.',
    effort: 'minutes',
  },
  'remediation/rotate-secrets': {
    label: 'Change the leaked secrets',
    summary: 'Assume the contents were copied. Change the database password, regenerate the WordPress keys and salts, and replace any API keys the file contained.',
    effort: 'hour',
  },
  'remediation/block-hidden-files': {
    label: 'Block hidden files',
    summary: 'Configure the web server to refuse requests for dot-files and folders such as .git and .env.',
    effort: 'minutes',
  },
  'remediation/move-backups-offsite': {
    label: 'Keep backups off the web server',
    summary: 'Store backups outside the public web folder or, better, off the server entirely.',
    effort: 'hour',
  },
  'remediation/disable-debug-logging': {
    label: 'Turn off public debugging',
    summary: 'Set WP_DEBUG and WP_DEBUG_DISPLAY to false on the live site, and keep any debug log outside the public web folder.',
    effort: 'minutes',
  },
  'remediation/restrict-user-enumeration': {
    label: 'Hide usernames',
    summary: 'Block the REST API users endpoint and author archives for visitors who are not signed in, for example with a security plugin.',
    effort: 'minutes',
  },
  'remediation/disable-xmlrpc': {
    label: 'Disable XML-RPC',
    summary: 'If you do not use the WordPress mobile app or Jetpack, block /xmlrpc.php at the web server or with a security plugin.',
    effort: 'minutes',
  },
  'remediation/disable-directory-listing': {
    label: 'Turn off directory listings',
    summary: 'Disable automatic directory indexes in the web server (for Apache: Options -Indexes).',
    effort: 'minutes',
  },
  'remediation/enforce-https': {
    label: 'Redirect everything to HTTPS',
    summary: 'Redirect all HTTP requests to HTTPS and make sure the WordPress and site addresses use https://.',
    effort: 'minutes',
  },
  'remediation/renew-certificate': {
    label: 'Renew the certificate',
    summary: 'Renew the TLS certificate and turn on automatic renewal (most hosts and Let’s Encrypt support this).',
    effort: 'minutes',
  },
  'remediation/install-valid-certificate': {
    label: 'Install a valid certificate',
    summary: 'Install a certificate from a trusted authority that covers every hostname the site is served on.',
    effort: 'hour',
  },
  'remediation/disable-legacy-tls': {
    label: 'Turn off old TLS versions',
    summary: 'Disable TLS 1.0 and 1.1 so only TLS 1.2 and 1.3 are offered.',
    effort: 'minutes',
  },
  'remediation/add-security-header': {
    label: 'Add the missing security header',
    summary: 'Add the header in your web server configuration, CDN, or with a security-headers plugin.',
    effort: 'minutes',
  },
  'remediation/fix-cookie-flags': {
    label: 'Harden cookie settings',
    summary: 'Make sure session cookies are sent with the Secure, HttpOnly and SameSite attributes.',
    effort: 'hour',
  },
  'remediation/protect-login': {
    label: 'Protect the login page',
    summary: 'Limit failed login attempts, require two-factor authentication for administrators, and consider restricting wp-admin by IP or putting it behind a firewall.',
    effort: 'hour',
  },
  'remediation/enable-two-factor': {
    label: 'Require two-factor authentication',
    summary: 'Install a two-factor authentication plugin and require it for every administrator and editor.',
    effort: 'minutes',
  },
  'remediation/incident-response': {
    label: 'Respond to a possible compromise',
    summary: 'Treat the site as compromised: keep a copy for investigation, restore clean files from a trusted backup, change every password and key, and check for backdoors. Consider professional help.',
    effort: 'day',
  },
  'remediation/restore-core-files': {
    label: 'Restore original WordPress files',
    summary: 'Reinstall the same WordPress version over the existing files (Dashboard → Updates → Re-install) to replace modified core files.',
    effort: 'minutes',
  },
  'remediation/fix-file-permissions': {
    label: 'Tighten file permissions',
    summary: 'Make wp-config.php readable only by the web server user (for example 400 or 440) and not writable by others.',
    effort: 'minutes',
  },
  'remediation/review-admin-accounts': {
    label: 'Review administrator accounts',
    summary: 'Remove administrator accounts that are not needed and downgrade the rest to the lowest role that works.',
    effort: 'minutes',
  },
} as const satisfies Record<string, RemediationDef>;
export type RemediationId = keyof typeof REMEDIATIONS;
