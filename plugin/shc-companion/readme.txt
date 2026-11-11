=== Security Health Check Companion ===
Contributors: securityhealthcheck
Tags: security, audit, health check
Requires at least: 5.8
Tested up to: 6.4
Requires PHP: 7.4
Stable tag: 0.1.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Read-only companion for the Security Health Check service. Lets a Pro audit see inside your site.

== Description ==

An outside scan can't see inactive plugins, exact versions, changed core files or PHP files hiding in uploads. This plugin reports those to your Security Health Check account once a day. It only reads. It never changes your site.

To connect, open **Tools > Security Health Check**, or run `wp shc pair <code> --service=<url>`. You need a Pro account and a verified site, and the code comes from the site page in your dashboard.

WP-CLI commands: `wp shc pair`, `wp shc send`, `wp shc status`, `wp shc report` (prints the report without sending it) and `wp shc disconnect`.

== What data is sent ==

Once a day, and when you press "Send report now", the plugin sends one signed report to the service address you entered:

* Site address, WordPress version and language, PHP version, whether this is a multisite.
* Every plugin and theme: name, folder, version, whether it is active, whether auto-updates are on. This plugin leaves itself out.
* Administrator accounts: the login name with the middle hidden (for example `s******n`) and the roles.
* Whether WP_DEBUG, WP_DEBUG_DISPLAY, WP_DEBUG_LOG and PHP display_errors are on.
* Whether wp-config.php exists and its permission bits (for example 0644). Never its contents.
* WordPress core files that differ from the official checksums, are missing, or are PHP files WordPress doesn't ship. File paths only.
* PHP files found in the uploads folder (path, size, change time), and PHP files in wp-content changed in the last 7 days (path, change time).

It never sends file contents, passwords, password hashes, keys, posts, comments, customer data or email addresses. The only file content it reads is the first 200 bytes of index.php files in uploads, to skip the empty "Silence is golden" ones.

To see the exact report, use **See exactly what is sent** on the settings page, or `wp shc report`.

== Installation ==

1. Upload the `shc-companion` folder to `/wp-content/plugins/` and activate it.
2. Go to Tools > Security Health Check and enter the service address and pairing code.

The service address must use https. Developers can allow http with `define( 'SHC_COMPANION_ALLOW_HTTP', true );` and pre-fill and lock the address with `define( 'SHC_COMPANION_SERVICE', 'https://...' );` in wp-config.php.

== Changelog ==

= 0.1.0 =
* First release.
