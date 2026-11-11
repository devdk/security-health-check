# Companion plugin: design and protocol

The companion plugin gives Pro users an inside view of their WordPress site. It reports what an outside scan can't see: inactive plugins, exact versions, modified core files, PHP in uploads, administrator accounts, 2FA, debug mode and `wp-config.php` permissions. The report merges this with the outside scan.

The protocol code lives in `packages/companion` (TypeScript). The plugin in `plugin/shc-companion` implements the same rules in PHP. Both are tested against `packages/companion/test/vectors.json`.

## Rules that hold everywhere

- The plugin is read-only. It never changes the site, never sends file contents, and never handles passwords or password hashes.
- Administrator logins are masked by the plugin before they leave the site (`shc-admin` becomes `s******n`). The API masks them again on arrival.
- The inside audit is a Pro feature. Pairing needs Pro and a verified site. Reports from a site whose owner is no longer on Pro are refused.
- Every report is signed with the site key, carries a timestamp within 5 minutes of the server clock, and a nonce that can't be reused.

## Pairing

1. The owner clicks **Connect the plugin** on the site page. The API creates a one-time code and shows it once, with the service address (`WEB_BASE_URL`).
   - Code: 10 Crockford base32 characters, shown as `ABCDE-FGHJK` (50 bits). Valid for 15 minutes (`PLUGIN_PAIRING_CODE_MINUTES`).
   - Only `hashPairingCode(normalizePairingCode(code))` is stored. Creating a new code removes the site's unused ones.
2. The site admin enters the service address and code in the plugin (**Tools → Security Health Check**) or runs `wp shc pair <code> --service=<address>`.
3. The plugin calls `POST {service}/api/plugin/pair` with JSON `{ "code", "homeUrl", "pluginVersion" }`.
4. The API checks, in this order:
   1. The code exists, is unused and unexpired. Unknown, used and expired codes all get the same `400 invalid_code`.
   2. The host of `homeUrl` is the site's domain or its `www.` twin. Otherwise `400 site_mismatch`.
   3. The owner is on Pro (`403 upgrade_required`) and the site is verified (`403 not_verified`).
5. The API marks the code used, revokes the site's previous keys, and creates a key:
   - `keyId`: random UUID.
   - `key = deriveSiteKey(PLUGIN_KEY_SECRET, keyId)`: base64url HMAC-SHA256 of `shc-site-key/v1:<keyId>`, 43 characters.
   - Stored: `keyId`, `hashSiteKey(key)` (SHA-256 hex), `expiresAt` (365 days, `PLUGIN_KEY_TTL_DAYS`). The key itself is never stored.
6. Response `201 { "keyId", "key", "expiresAt" }`. This is the only time the key is sent. The plugin stores it in a non-autoloaded option and sends its first report right away.

`POST /api/plugin/pair` takes no session and is limited per IP like the sign-in endpoints.

## Signed reports

`POST {service}/api/plugin/reports`, `Content-Type: application/json`, body at most 512 KB. Headers:

| Header | Value |
| --- | --- |
| `X-SHC-Key-Id` | the key id (UUID, lowercase) |
| `X-SHC-Timestamp` | Unix time in seconds |
| `X-SHC-Nonce` | 16–64 characters of `[A-Za-z0-9_-]`, new for every request |
| `X-SHC-Signature` | `v1=` + lowercase hex HMAC-SHA256 |

The HMAC key is the site key's text (the 43 characters, as UTF-8). The signed string joins six lines with `\n` and has no trailing newline:

```
SHC-HMAC-SHA256-V1
POST
/api/plugin/reports
<timestamp>
<nonce>
<lowercase hex SHA-256 of the raw body bytes>
```

The path is the constant `/api/plugin/reports`, never the URL the request arrived on, so proxies can't break signatures.

The API checks, in this order, and stops at the first failure:

| Check | Failure |
| --- | --- |
| Headers present and well-formed | `401 invalid_signature` |
| Timestamp within ±300 s | `401 stale_request` |
| Key exists, not revoked | `401 invalid_key` |
| Key not expired | `401 key_expired` (the plugin asks the admin to pair again) |
| `hashSiteKey(deriveSiteKey(secret, keyId))` equals the stored hash | `401 invalid_key` |
| Signature over the raw body matches (constant-time) | `401 invalid_signature` |
| Per-site rate limit (`PLUGIN_REPORTS_PER_HOUR`, default 12) | `429` |
| Owner still on Pro | `403 upgrade_required` |
| Site ownership still verified (re-checked when the last check is over 24 hours old, as before a scan) | `403 not_verified` |
| Body parses as JSON and passes `parseInsideReport` | `400 invalid_report` with up to 10 messages |
| Host of `site.homeUrl` is the domain or its `www.` twin | `400 site_mismatch` |
| `(keyId, nonce)` not seen before (unique index) | `409 replayed` |

On success the API stores the report in `plugin_reports` (logins masked again), creates a queued scan with `kind = 'inside'` and `trigger = 'plugin'`, queues it, updates the key's `lastUsedAt`, and answers `202 { "reportId", "scanId" }`.

## Report payload (schema 1)

`InsideReportSchema` in `packages/companion/src/report.ts` is the definition; unknown fields are refused. In short:

- `site.homeUrl`, `site.siteUrl`, `site.multisite`; `wordpress.version`, `wordpress.locale`; `php.version`; `plugin.version`.
- `plugins[]`: `slug` (directory name, or file name without `.php` for single-file plugins), `file` (basename such as `contact-form-7/wp-contact-form-7.php`), `name`, `version` (or null), `active` (network-active counts as active), `autoUpdate`. The companion plugin leaves itself out.
- `themes[]`: `slug`, `name`, `version`, `active`, `parent` (the template slug for child themes), `autoUpdate`.
- `admins[]`: users with the `administrator` role, `login` masked, `roles`.
- `debug`: `WP_DEBUG`, `WP_DEBUG_DISPLAY`, `WP_DEBUG_LOG` (true when it is true or a path), and PHP `display_errors`.
- `configFile`: whether `wp-config.php` was found in the WordPress root or one level up, and its permission bits as an octal string (null on hosts without POSIX permissions).
- `coreIntegrity`: comparison with `get_core_checksums()` for the installed version and the language of the installed package (`$wp_local_package` from `wp-includes/version.php`, `en_US` when unset), read the way core's update checks read them. The Site Language setting is not used: it often differs from the package. `modified` and `missing` list core files (paths relative to the WordPress root, `wp-content/` excluded). `unexpected` lists `.php` files in `wp-admin/` or `wp-includes/` that WordPress doesn't ship. `status: 'unavailable'` with a `reason` when the checksums couldn't be fetched. At most 100 paths per list, `truncated` when there were more.
- `uploadsPhp`: files under the uploads folder whose extension is `.php`, `.phtml`, `.php3`–`.php8`, `.phar` or `.pht` (case-insensitive), paths relative to the uploads folder. An `index.php` of at most 200 bytes whose content is only `<?php`, optional whitespace, an optional `// Silence is golden.` comment and an optional `?>` is skipped. At most 20,000 files are looked at (`scanned`) and 100 reported.
- `recentPhp`: `.php` files under `wp-content` changed in the last 7 days, paths relative to `wp-content`. Skipped: `uploads/`, `cache/`, `upgrade/`, `upgrade-temp-backup/`, `languages/`, and folders where plugins keep routinely rewritten PHP data or settings (`wflogs/`, `w3tc-config/`, `wp-rocket-config/`, and `wp-cache-config.php`). `packageUpdated` is true when the file lies inside `plugins/<slug>/` or `themes/<slug>/` and that package's marker file (the plugin's main file, or the theme's `style.css`) changed within one hour of it: that is what an update looks like. When more than 100 files qualify, those with `packageUpdated: false` are listed first, then the newest.

## Turning a report into findings

The worker processes inside scans with `analyseInside(report, { vulns, releases })` in `packages/scanner`. No request goes to the site.

Components, all `sources: ['plugin']`, `versionConfidence: 'confirmed'`, with `active` set for plugins and themes: core `wordpress`, `php`, every plugin and every theme.

The stage-2 modules `vuln-match` and `outdated-software` then run over these components unchanged, so inactive plugins are matched against vulnerability data too.

Inside rules, check ids `plugin.<rule>`:

| Rule | Exposure | Severity, confidence |
| --- | --- | --- |
| PHP branch no longer supported (`phpSupport`) | `php-unsupported` | high, confirmed |
| Each inactive plugin; each inactive theme except the active theme's parent | `inactive-component-installed` | low, confirmed |
| No active plugin from the known 2FA list | `no-two-factor-auth` | medium, likely |
| More than 3 administrators | `excessive-administrators` | low, confirmed |
| `WP_DEBUG` on | `debug-mode-enabled` | medium when errors are displayed, otherwise low |
| `wp-config.php` group- or world-writable / only world-readable | `config-file-permissions-weak` | medium / low |
| Any `modified` or `unexpected` core file | `core-files-modified` | critical, confirmed |
| Any PHP file in uploads | `php-in-uploads` | critical, confirmed |
| Recent PHP changes with `packageUpdated: false` | `suspicious-file-changes` | high, possible |

Inside findings are never in the free selection (`visibleInFree` false). Possible-compromise findings still show their title and explanation to every plan, as for outside scans.

## The merged report

Each scan's report is the site's picture at the moment that scan finished: the scan itself plus its counterpart, the most recent completed scan of the other kind that finished at or before it, no more than 30 days earlier. One function in `packages/core` finds the counterpart, so the worker and the API always pair the same scans.

- Where both views can see something (the exposure's `detectedBy` includes `plugin`) and the finding concerns a component the inside view listed, the inside view wins: the outside finding is dropped. This removes outside version guesses that the inside view contradicts.
- Everything else from both scans is kept. Components are merged the same way.
- The score and grade are computed over the merged findings. The worker stores that merged score on the scan, so history chips and the dashboard show the site's overall score at each point in time.
- Each revealed finding says where it came from: `source: 'outside' | 'inside'`. Locked findings stay as they are (id, severity, area).

Free users can open the report of the newest completed scan of any kind, as before.

## Dashboard API

Session endpoints, owner only. Errors use the API's usual body: `{ "error": "<code>", "message": "<text for people>" }`.

```ts
interface PluginStatus {
  /** False when PLUGIN_KEY_SECRET is unset: pairing is switched off on this server. */
  available: boolean;
  status: 'not_connected' | 'connected' | 'expired';
  connectedAt: string | null; // when the current key was issued
  expiresAt: string | null;
  lastReportAt: string | null; // newest plugin report received
  lastScanId: string | null; // the inside scan built from it
  pluginVersion: string | null;
}
```

| Method and path | Result |
| --- | --- |
| `GET /api/sites/:siteId/plugin` | `200 { plugin: PluginStatus }` |
| `POST /api/sites/:siteId/plugin/pairing-code` (body `{}`) | `201 { pairing: { code: "ABCDE-FGHJK", expiresAt, serviceUrl } }`. `403 upgrade_required`, `403 not_verified`, `503 plugin_unavailable` |
| `DELETE /api/sites/:siteId/plugin` | `200 { plugin: PluginStatus }` after revoking every key of the site |

The plugin zip is served by the dashboard at `/downloads/shc-companion.zip`.

Scan lists (`GET /api/sites/:siteId/scans`) include each scan's `kind`. The report (`GET /api/scans/:scanId/report`) keeps its current fields and adds:

```ts
interface ReportView {
  // ...existing fields, which describe the scan the report was opened for...
  kind: 'external' | 'inside';
  outside: { scanId: string; finishedAt: string; baseUrl: string | null; requestCount: number } | null;
  inside: { scanId: string; finishedAt: string; pluginVersion: string | null } | null;
  components: Array<{ type; slug; name; version; versionConfidence; active: boolean | null }>;
}
interface RevealedFinding {
  // ...existing fields...
  source: 'outside' | 'inside';
}
```
