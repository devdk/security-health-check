# Security Health Check

An attacker's-eye security audit for WordPress sites. Owners add a site, prove they own it, and get a scored security report. A companion WordPress plugin adds an inside-view audit.

> **Status: Phase 6.** Done: scaffold, auth, site management, ownership verification, the security ontology, the scan queue and worker, all external checks, the daily vulnerability intelligence, scoring, reports with free/paid visibility, PDF export, plans (stub payments), weekly scans, fix requests, and the companion plugin with signed inside reports merged into one report. Next: context engineering and the AI harness. A full README follows in the hardening phase.

## Reports, scores and plans

**Score and grade** (`packages/report/src/score.ts`): every finding takes points off 100 according to its severity: critical 30, high 15, medium 6, low 2, info 0. The deduction is scaled by confidence (confirmed ×1, likely ×0.8, possible ×0.5), and repeats of the same problem count less each time. Caps keep the grade honest:
- a likely or confirmed sign of compromise caps the score at 19 (F); a merely possible one (a heuristic) is shown as a warning but doesn't cap;
- a confirmed or likely critical caps it at 49 (F);
- a confirmed or likely high caps it at 74 (C).

Grades are A 90+, B 80+, C 70+, D 60+, otherwise F. The score is stored on the scan when it finishes.

**Free vs Pro**: the full scan always runs, and the API decides what is visible at read time (`buildReportView`). The dashboard never decides.

| | Free | Pro |
|---|---|---|
| Score, grade, counts per severity | ✓ | ✓ |
| Findings in full | about a third, chosen round-robin across severities when the scan finishes | all |
| Other findings | locked: only severity and area (e.g. "Publicly served files") are sent | – |
| Possible-compromise findings | title, explanation and evidence always shown; fix locked | full |
| Step-by-step fix guides | for the findings shown | ✓ |
| PDF export, scan history, weekly scans, "request a fix" | – | ✓ |
| Inside view (companion plugin) | – | ✓ |

Locked findings are built field by field and the response schema forbids extra fields, so nothing else can leak. Tests check the raw response bodies. Inside findings are never part of the free selection.

**Payments**: the `PaymentProvider` interface (`packages/core/src/billing.ts`) has a **stub** for development, which switches plans instantly from the Account page, and **none**. The stub is refused in production by config; a real provider (Stripe, Paddle…) plugs in behind the same interface.

**PDF export**: the report is rendered to self-contained HTML (inline CSS, no scripts, every value escaped). Headless Chromium in the `pdf` container (Gotenberg, MIT) then prints it, with JavaScript disabled and network access limited to its own temp files.

**Attribution**: findings from Wordfence keep the record link and the Defiant and MITRE notices. Findings from NVD carry the NVD notice. The report and the PDF show them in a "Data sources" section.

**Weekly scans**: Pro sites can opt in. A scheduler checks every 10 minutes, and each scheduled scan follows the same rules as a manual one (re-verified ownership, one scan at a time, cooldown). Weekly scans switch off when the owner leaves Pro.

## Companion plugin (inside view)

A read-only WordPress plugin (`plugin/shc-companion`, PHP 7.4+, WordPress 5.8+, no dependencies) reports what a scan from outside can't see. The full design and wire protocol are in [docs/companion-plugin.md](docs/companion-plugin.md).

- **What it sends**: every plugin and theme with its version and whether it is active; WordPress and PHP versions; administrator accounts with logins masked on the site (`s******n`); debug settings; the permission bits of `wp-config.php`; core files that differ from WordPress.org's checksums; PHP files in the uploads folder; PHP files changed in the last 7 days that no update explains. Never file contents, passwords or keys. **Tools → Security Health Check → See exactly what is sent** shows the JSON.
- **Pairing**: on the site page (Pro, verified site) choose **Connect the plugin**. The dashboard shows the service address and a one-time code (15 minutes). The site admin enters both in the plugin, or runs `wp shc pair <code> --service=<address>`. The API returns a site key derived from `PLUGIN_KEY_SECRET` and stores only its hash. Keys expire after a year; **Disconnect** on the dashboard revokes them.
- **Signed reports**: sent right after pairing, then daily by WP-Cron, or with **Send report now** / `wp shc send`. Each carries an HMAC-SHA256 signature, a timestamp (±5 minutes) and a single-use nonce. The API checks all three and a strict schema before storing anything.
- **Merged report**: each report becomes an inside scan, analysed by the worker without contacting the site. A report pairs a scan with the newest scan of the other kind from the previous 30 days. Where both views see the same software, the inside view wins, because it knows the installed versions exactly. Findings carry an "Inside view" or "Outside scan" tag, and the score covers both.
- **Install**: the dashboard serves the plugin as `/downloads/shc-companion.zip` (built into the web image). Upload it in WordPress under Plugins → Add New → Upload Plugin.
- **Settings**: `PLUGIN_KEY_SECRET` (API only; generated by `npm run setup:env`; empty switches pairing off; changing it disconnects every plugin). In the plugin, `SHC_COMPANION_SERVICE` in `wp-config.php` pre-fills and locks the service address, and plain http is refused unless `SHC_COMPANION_ALLOW_HTTP` is true (development only).
- **Note**: `wp shc send` reports the PHP version of the command line, which some hosts run differently from the web server. The daily report runs inside WordPress and reports the web server's PHP.

## Vulnerability intelligence

The worker refreshes a local cache once a day (`INTEL_REFRESH_CRON`, default 03:17 UTC), and also at startup when the cache is empty or more than a day old. Each source sits behind an adapter in `packages/intel`:

| Source | Used for | Notes |
|---|---|---|
| **Wordfence Intelligence** (v3 production feed) | WordPress core, plugin and theme vulnerabilities | Free for commercial use. **Needs a free API key** in `WORDFENCE_API_KEY` (wordfence.com → Account → Integrations); skipped until set. Attribution (record link, Defiant and MITRE copyright notices) is stored with every record for the reports. |
| **NVD** CVE API 2.0 | PHP runtime vulnerabilities (`cpe:2.3:a:php:php`) | Free; `NVD_API_KEY` optional (raises the rate limit). Display "uses data from the NVD API but is not endorsed or certified by the NVD". |
| **WordPress.org** APIs | Latest core release and the status of every version; latest plugin and theme versions | Core is refreshed daily. Plugins and themes are looked up on first sight and cached for a day. |
| **OSV** | – | Adapter slot only: OSV has no WordPress or PHP-runtime data, and some of its sources are non-commercial. |
| **php.net** support dates | PHP end-of-life | Kept in code (`packages/scanner/src/data/php-branches.ts`); a test fails when a new branch is due. |

Run the refresh by hand with `npm run intel:sync -w @shc/worker`.

## Checks

| Module | Looks for | Requests |
|---|---|---|
| wp-detect | WordPress and its version (generator tag, feed, core assets) | 2 |
| plugins-themes | Plugins and themes, with versions from readme.txt and style.css | 1 per item (up to 30 plugins) |
| php-version | PHP version and end of life (from response headers); web server | 0 (reuses the home page) |
| exposed-files | wp-config backups, .env, .git, SQL dumps, archives, debug.log, phpinfo | HEAD per path; a 4 KB GET only when it exists |
| user-enum | Usernames via the REST API and author archives | ≤ 4 |
| xmlrpc | A live xmlrpc.php (GET only, never POST) | 1 |
| directory-listing | Open folder listings in wp-content and wp-includes | 4 |
| tls | Certificate validity, expiry, trust, hostname; TLS 1.0/1.1; HTTP→HTTPS redirect | ≤ 3 |
| headers | HSTS, CSP, frame protection, nosniff, Referrer-Policy, Permissions-Policy, session cookie flags | 0–1 |
| admin-exposure | An open login page with no visible protection (never attempts a login) | ≤ 2 |
| vuln-match | Detected versions against the vulnerability cache (PHP CVEs grouped) | 0 |
| outdated-software | Detected versions against WordPress.org's latest releases | 0 to the site |

Evidence never stores file contents, cookie values or full usernames. The rate-limit slot is taken after DNS resolution and immediately before each request is sent, with a 50 ms margin, so the target sees at most 2 requests per second. The end-to-end script verifies this against the test site's access log.

## How a scan works

```
dashboard ──POST /api/sites/:id/scans──▶ API ──(re-verify ownership, cooldown, one at a time)──▶ BullMQ queue
                                                                                                    │
            site_components + findings ◀── worker ◀── re-verify ownership again ◀────────────────────┘
                                             │
                                             └─ scanner engine: PoliteClient (≤2 req/s per site, shared via Valkey;
                                                request cap; verified domain only; GET/HEAD; honest User-Agent)
                                                  stage 1: wp-detect, plugins-themes   (gather facts)
                                                  stage 2: vuln-match                  (analyse facts)
```

- **Check modules** live in `packages/scanner/src/modules/`. Each one exports `run(target, context) → Finding[]` and can only reach the site through `context.http`, which enforces the scanning rules in one place.
- **Every finding points at an ontology concept** (`packages/ontology`), for example `exposure/known-vulnerable-component`. The concept links to its CWE weakness, the CAPEC attack it enables, the controls that reduce it and the remediations that fix it. Report text is generated from the concept. Export the vocabulary with `npm run export -w @shc/ontology` (writes `docs/ontology.jsonld`).
- **Detected software** is stored per scan in `site_components`, and findings link to the component they concern.
- **Limits** (in `.env`; the defaults are the product's promises): `SCAN_RATE_PER_SECOND` (at most 2), `SCAN_MAX_REQUESTS` (150), `SCAN_COOLDOWN_MINUTES` (15), `SCAN_TIMEOUT_SECONDS` (300).

## Local test WordPress (end-to-end)

A deliberately outdated WordPress (6.4.2 on PHP 8.1, with Contact Form 7 5.3.1 (CVE-2020-35489), a leftover `wp-config.php.bak` holding fake values, and a public `debug.log`) runs under a separate compose profile. Its updates are disabled, it is published on 127.0.0.1 only, and the scanner reaches it as `http://wordpress.test`. The companion plugin is mounted read-only and activated, and the setup plants problems only the inside view can see: a PHP file in uploads, a changed core file, a stray must-use plugin and three extra administrators. All contents are harmless.

```bash
docker compose --profile testwp up -d
node scripts/e2e-scan.mjs
```

The end-to-end script signs up through the real API, verifies ownership with the file method, runs a scan, and then reads the test site's access log to confirm the scanner never exceeded 2 requests per second and always sent its User-Agent. It then upgrades to Pro, pairs the plugin with WP-CLI, and checks the merged report, single-use codes, masked logins and that a disconnected plugin is refused.

To re-record the HTTP fixtures that module tests replay:

```bash
npm run record-fixtures -w @shc/scanner
```

## Ownership verification

A site can't be scanned until its owner proves control, using either method:

| Method | What the owner does |
|---|---|
| DNS | Adds a TXT record `_shc-verify.<domain>` = `shc-verify=<token>` (a record on the domain itself also counts) |
| File | Serves `https://<domain>/shc-verify-<token>.txt` containing exactly `shc-verify=<token>` |

- Tokens are 128-bit, unique per site and per owner, so two people can each verify the same domain independently.
- File checks require an exact body match, so "soft 404" pages that echo the path don't pass. They follow redirects only within the same site (apex ↔ www), and fall back to plain HTTP only when HTTPS is unreachable.
- Before every scan, `ensureFreshVerification` (in `packages/core`) re-checks ownership with the stored method whenever the last success is more than 24 hours old. If the re-check fails, the scan is refused.

All outbound requests go through `SafeFetcher` (`packages/net`):
- http/https on ports 80 and 443 only;
- refuses any hostname that resolves to a private, loopback, link-local, metadata or reserved address;
- pins the socket to the vetted IP, which defeats DNS rebinding;
- re-checks every redirect and caps time and response size;
- always sends the honest `SecurityHealthCheck` User-Agent, which links to the public `/scanner` page.

## Prerequisites

- Docker Desktop (Compose v2)
- Node.js 22.12 or newer (only needed to run things outside Docker)

## Quick start (everything in Docker)

```bash
npm install
npm run setup:env          # writes .env with random DB and Redis passwords
docker compose up --build  # api, worker, web, postgres, valkey, one-off migrate
```

Open http://localhost:8080. In development, emails are written to the API log instead of being sent:

```bash
docker compose logs -f api
```

Copy the confirmation link from the log into your browser to verify your account.

## Local development (hot reload)

Run only the databases in Docker and the apps on your machine:

```bash
docker compose up -d postgres redis
npm run db:migrate
npm run dev:api      # http://localhost:3000
npm run dev:web      # http://localhost:5173 (proxies /api to :3000)
npm run dev:worker
```

## Tests

Tests use the real Postgres and Valkey containers, with separate test databases (`shc_test`, Valkey db 1). They never touch live third-party sites.

```bash
docker compose up -d postgres redis
npm test
```

## Useful scripts

| Script | What it does |
|---|---|
| `npm run setup:env` | Creates `.env` from `.env.example` with generated secrets (won't overwrite) |
| `npm run db:generate` | Generates a SQL migration after editing `packages/db/src/schema.ts` |
| `npm run db:migrate` | Applies migrations to `DATABASE_URL` |
| `npm run typecheck` | Type-checks every workspace |
| `npm run build` | Bundles api/worker (esbuild) and builds the web app (Vite) |
| `npm run test:plugin` | Lints the companion plugin's PHP and runs its tests (in the WP-CLI image; needs Docker) |

## Layout

```
apps/api        Fastify API: auth, sites, scans, reports, PDF, billing, plugin pairing and signed ingestion
apps/worker     BullMQ worker: outside and inside scans, daily intel refresh, weekly scans
apps/web        React + Vite dashboard
packages/companion Plugin protocol: pairing codes, site keys, request signing, inside-report schema, test vectors
plugin/         The companion WordPress plugin (PHP) and its tests
packages/config Env loading and validation: the only code that reads process.env
packages/core   Business rules shared by API and worker (audit log, re-verify before scan, scan requests, queue)
packages/db     Drizzle schema, generated SQL migrations, DB client
packages/net    SSRF-safe HTTP client, IP policy, DNS, ownership checks
packages/ontology  Security ontology: exposures, CWE/CAPEC mappings, controls, remediations, JSON-LD export
packages/scanner   Scan engine, polite HTTP client, rate limiter, check modules, recorded fixtures
packages/intel     Vulnerability source adapters (Wordfence, NVD, OSV slot), WordPress.org release data, sync jobs
packages/report    Score and grade, free-plan selection, reveal logic (free vs Pro), report HTML for PDF
packages/shared Domain constants and validation shared by every app (incl. the browser)
docker/         Dockerfiles and nginx config
scripts/        Build and setup helpers
```

## Security model (product)

- **Secrets** live only in `.env` (gitignored) and are read once by `packages/config`, which refuses to start on invalid values. In production it also requires https and Secure cookies.
- **Passwords** are hashed with argon2id (OWASP parameters). Sign-in takes about the same time whether or not the account exists. Accounts lock for 15 minutes after 10 failed attempts.
- **Sessions** use a random 256-bit token in an `HttpOnly`, `Secure`, `SameSite=Lax` cookie. Only its SHA-256 is stored, and sessions are revoked on sign-out and on password reset.
- **Email links** carry single-use tokens (stored hashed) in the URL fragment, so they never appear in server logs or `Referer` headers.
- **No account enumeration**: registration and password reset give the same response whether or not the email exists.
- **CSRF**: the API accepts JSON bodies only and checks `Origin` on state-changing requests, on top of SameSite cookies.
- **Rate limits**: per user (or per IP when signed out) globally, stricter per-IP limits on auth endpoints, stored in Valkey.
- **Queries** go through Drizzle and are always parameterised. Every endpoint validates its input against a schema, and response schemas strip unexpected fields.
- **Containers** run as non-root with read-only filesystems, dropped capabilities and `no-new-privileges`. Only the web port is published, and only on 127.0.0.1.

## Git policy

Commits are authored by people only. `.githooks/commit-msg` rejects any commit that credits Claude or Anthropic as an author, co-author or contributor. Enable it in a fresh clone with:

```bash
git config core.hooksPath .githooks
```

## Choices to note

- **Valkey instead of Redis server.** Redis 7.4+ moved to restrictive licences (RSAL/SSPL, then AGPL in 8.0). Valkey is the BSD-licensed fork with the same protocol, and BullMQ and ioredis support it. To use Redis instead, change the image in `docker-compose.yml`.
- **Plugin keys** (Phase 6) are derived from a server master secret with HMAC, so the database stores only a hash of each key and can still verify HMAC-signed reports.
