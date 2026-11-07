# Security Health Check

An attacker's-eye security audit for WordPress sites. Owners add a site, prove they own it, and get a scored security report. A companion WordPress plugin adds an inside-view audit.

> **Status: Phase 3.** Done: scaffold, auth, site management, ownership verification, the security ontology, the scan queue and worker, and the first three checks (WordPress detection, plugins and themes, known vulnerabilities). Reports, scoring and the remaining checks come next. A full README follows in the hardening phase.

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

A deliberately outdated WordPress (6.4.2 with Contact Form 7 5.3.1, CVE-2020-35489) runs under a separate compose profile. Its updates are disabled, it is published on 127.0.0.1 only, and the scanner reaches it as `http://wordpress.test`.

```bash
docker compose --profile testwp up -d
node scripts/e2e-scan.mjs
```

The end-to-end script signs up through the real API, verifies ownership with the file method, runs a scan, and then reads the test site's access log to confirm the scanner never exceeded 2 requests per second and always sent its User-Agent.

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

## Layout

```
apps/api        Fastify API (auth now; sites, scans, reports, plugin ingestion later)
apps/worker     BullMQ worker (skeleton now; scan jobs in Phase 3)
apps/web        React + Vite dashboard
packages/config Env loading and validation: the only code that reads process.env
packages/core   Business rules shared by API and worker (audit log, re-verify before scan, scan requests, queue)
packages/db     Drizzle schema, generated SQL migrations, DB client
packages/net    SSRF-safe HTTP client, IP policy, DNS, ownership checks
packages/ontology  Security ontology: exposures, CWE/CAPEC mappings, controls, remediations, JSON-LD export
packages/scanner   Scan engine, polite HTTP client, rate limiter, check modules, recorded fixtures
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
