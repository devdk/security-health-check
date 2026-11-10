import type { RemediationId } from './vocabulary';

/**
 * Step-by-step fix guides, one per remediation. Written for site owners, not developers:
 * where something needs a developer or the host, the step says so. Every remediation must
 * have a guide (enforced by the type below).
 */
export const GUIDES = {
  'remediation/update-wordpress-core': [
    'Make a full backup of files and database (most hosts have a one-click backup).',
    'Sign in to WordPress and go to Dashboard → Updates.',
    'Click "Update to version …" and wait for it to finish; do not close the page.',
    'Open a few pages of the site to check it still works, then run a new scan.',
  ],
  'remediation/update-affected-component': [
    'Make a backup of the site.',
    'Go to Plugins (or Appearance → Themes) and find the item named in this finding.',
    'Click "Update now". If no update is offered, check the developer’s site; premium plugins often update from their own account page.',
    'If no fixed version exists yet, deactivate and delete it until one is released, or replace it with an alternative.',
    'Run a new scan to confirm the issue is gone.',
  ],
  'remediation/remove-unused-component': [
    'Go to Plugins → Installed Plugins and look for anything marked "Inactive".',
    'For each one you do not need, click "Delete" (deactivating is not enough: the files stay on the server).',
    'Do the same under Appearance → Themes, keeping only your active theme and one default theme as a fallback.',
  ],
  'remediation/enable-auto-updates': [
    'Go to Plugins → Installed Plugins and click "Enable auto-updates" for each trusted plugin.',
    'Go to Appearance → Themes, open each theme and enable auto-updates.',
    'In Dashboard → Updates, choose to keep WordPress updated automatically for all new versions.',
    'Make sure you have automatic daily backups so a bad update can be rolled back.',
  ],
  'remediation/hide-version-info': [
    'Install a reputable security plugin that offers "remove WordPress version" or "hide generator tag".',
    'Turn that option on, then view your page source and check the generator tag is gone.',
    'Keep updating WordPress regardless: hiding the number only slows attackers down.',
  ],
  'remediation/block-readme-files': [
    'Ask your host or developer to block web access to readme.txt and changelog.txt files under /wp-content/.',
    'On Apache this is a short rule in .htaccess; on nginx a location block. Many security plugins can add it for you.',
    'Check that https://your-site/wp-content/plugins/<a plugin>/readme.txt now returns "Forbidden" or "Not found".',
  ],
  'remediation/hide-php-version': [
    'In your hosting control panel, look for PHP settings (often "PHP Options" or "php.ini editor").',
    'Set expose_php to Off and save.',
    'If you cannot find it, ask your host to turn off the X-Powered-By header for your site.',
  ],
  'remediation/upgrade-php': [
    'Check in Tools → Site Health that your plugins and theme support a current PHP version.',
    'Make a backup, then switch the site to a supported PHP version in your hosting control panel (look for "PHP version" or "PHP selector").',
    'Browse the site and the admin area to check nothing broke; switch back immediately if something did, and ask a developer to fix the incompatible plugin.',
    'If your host cannot offer a supported PHP version, plan a move to one that can.',
  ],
  'remediation/remove-exposed-file': [
    'Using your host’s file manager or SFTP, delete the file named in this finding (or move it outside the public web folder).',
    'Reload its address in a browser and check you now get "Not found".',
    'Ask your host for access logs and check whether anyone downloaded it before you removed it.',
    'Find out how it got there (a backup plugin, an editor, a developer) so it does not come back.',
  ],
  'remediation/rotate-secrets': [
    'Change the database password in your hosting control panel, then update DB_PASSWORD in wp-config.php to match.',
    'Generate new keys at https://api.wordpress.org/secret-key/1.1/salt/ and replace the AUTH_KEY … NONCE_SALT lines in wp-config.php. This signs everyone out.',
    'Replace any other API keys or passwords the file contained (payment, email, storage services).',
    'Reset the passwords of all administrator accounts.',
  ],
  'remediation/block-hidden-files': [
    'Ask your host or developer to deny web access to any file or folder whose name starts with a dot (.git, .env, .svn).',
    'Better still, keep these out of the public web folder entirely: deploy only the built site, not the repository.',
    'Check that https://your-site/.git/HEAD and https://your-site/.env now return "Forbidden" or "Not found".',
  ],
  'remediation/move-backups-offsite': [
    'Delete any backup archives or database exports from the public web folder.',
    'Configure your backup plugin to store backups in remote storage (for example S3, Google Drive or Dropbox), not on the server itself.',
    'If backups must stay on the server, keep them in a folder above the public web root.',
  ],
  'remediation/disable-debug-logging': [
    "Open wp-config.php and set define( 'WP_DEBUG', false ); and define( 'WP_DEBUG_DISPLAY', false );",
    'If you need logging, point WP_DEBUG_LOG to a file outside the public folder instead of wp-content/debug.log.',
    'Delete the existing wp-content/debug.log file.',
  ],
  'remediation/restrict-user-enumeration': [
    'Install a reputable security plugin with a "stop user enumeration" or "disable REST API users endpoint" option and enable it.',
    'Check that https://your-site/wp-json/wp/v2/users no longer lists users and that /?author=1 no longer redirects to an author page.',
    'Give administrators a display name that differs from their login name.',
  ],
  'remediation/disable-xmlrpc': [
    'Confirm you do not use the WordPress mobile app, Jetpack, or other tools that need XML-RPC.',
    'Enable "disable XML-RPC" in a security plugin, or ask your host to block requests to /xmlrpc.php.',
    'Check that https://your-site/xmlrpc.php now returns "Forbidden".',
  ],
  'remediation/disable-directory-listing': [
    'Ask your host to turn off automatic directory indexes for your site.',
    'On Apache you can add the single line "Options -Indexes" to the .htaccess file in the site root.',
    'Check that https://your-site/wp-content/uploads/ no longer shows a list of files.',
  ],
  'remediation/enforce-https': [
    'Make sure the site has a valid certificate (most hosts provide free Let’s Encrypt certificates).',
    'In Settings → General, change both WordPress Address and Site Address to start with https://.',
    'Turn on "force HTTPS" or "redirect HTTP to HTTPS" in your hosting panel or CDN.',
    'Check that http://your-site/ now redirects to https://.',
  ],
  'remediation/renew-certificate': [
    'In your hosting control panel or CDN, open the SSL/TLS section and renew the certificate.',
    'Turn on automatic renewal so this does not happen again.',
    'Check the new expiry date by clicking the padlock in your browser.',
  ],
  'remediation/install-valid-certificate': [
    'Request a certificate covering every name the site uses (for example example.com and www.example.com). Free Let’s Encrypt certificates work.',
    'Install it in your hosting control panel or CDN, replacing the self-signed or mismatched one.',
    'Open the site in a private browser window and check there is no security warning.',
  ],
  'remediation/disable-legacy-tls': [
    'In your hosting panel, CDN or server configuration, set the minimum TLS version to 1.2.',
    'If you cannot change it, ask your host to disable TLS 1.0 and 1.1.',
    'Run a new scan to confirm.',
  ],
  'remediation/add-security-header': [
    'Decide where to add headers: your CDN (often easiest), your web server configuration, or a security-headers plugin.',
    'Add the header named in this finding. Sensible starting values: Strict-Transport-Security "max-age=31536000"; X-Content-Type-Options "nosniff"; X-Frame-Options "SAMEORIGIN"; Referrer-Policy "strict-origin-when-cross-origin"; Permissions-Policy "camera=(), microphone=(), geolocation=()".',
    'A Content-Security-Policy needs care: start with Content-Security-Policy-Report-Only and tighten it before enforcing, or ask a developer.',
    'Check the site still works, then run a new scan.',
  ],
  'remediation/fix-cookie-flags': [
    'Note the cookie names listed in this finding and which plugin sets them (the name usually gives it away).',
    'Update that plugin; recent versions usually set cookies correctly.',
    'If the issue remains, ask your host or developer to enable session.cookie_secure, session.cookie_httponly and session.cookie_samesite in PHP settings, or contact the plugin author.',
  ],
  'remediation/protect-login': [
    'Install a reputable security plugin and enable "limit login attempts" (or login rate limiting).',
    'Require two-factor authentication for every administrator (see the two-factor guide).',
    'Optionally add a CAPTCHA to the login form, or restrict /wp-admin to your own IP addresses through your host.',
    'Make sure every administrator uses a long, unique password.',
  ],
  'remediation/enable-two-factor': [
    'Install a well-reviewed two-factor plugin (several free ones support authenticator apps).',
    'Turn on two-factor for your own account first and save the backup codes somewhere safe.',
    'Make two-factor mandatory for administrators and editors.',
  ],
  'remediation/incident-response': [
    'Do not delete anything yet. Make a full copy of the site files and database for investigation.',
    'Change every password: WordPress administrators, hosting control panel, SFTP, database. Regenerate the keys in wp-config.php.',
    'Restore clean files from a backup taken before the problem started, or reinstall WordPress core, plugins and themes from official sources.',
    'Look for unknown administrator accounts and remove them. Scan again, and consider a professional clean-up service if anything remains.',
    'If customer data may have been exposed, check your legal obligations to notify people.',
  ],
  'remediation/restore-core-files': [
    'Make a backup of the current site.',
    'Go to Dashboard → Updates and click "Re-install version …". This replaces core files with fresh copies.',
    'Run a new inside scan to check the modified files are gone. If they come back, follow the compromise guide.',
  ],
  'remediation/fix-file-permissions': [
    'Using your host’s file manager or SFTP, open the permissions of wp-config.php.',
    'Set them to 440 or 400 (readable by the web server only). If the site breaks, try 640 and ask your host which works.',
    'Check that no files under wp-content are writable by "everyone" (777).',
  ],
  'remediation/review-admin-accounts': [
    'Go to Users and filter by Administrator.',
    'Remove accounts that belong to people who no longer need access; reassign their content to another user.',
    'Change the rest to the lowest role that still lets them do their job (Editor, Author, or Shop Manager).',
  ],
} as const satisfies Record<RemediationId, readonly string[]>;
