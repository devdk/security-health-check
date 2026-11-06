# Security Health Check

An attacker's-eye security audit for WordPress sites. Owners add a site, prove they own it, and get a scored security report. A companion WordPress plugin adds an inside-view audit.

> **Status: Phase 1 of 7.** Scaffold, Docker Compose, config, database schema and migrations, and authentication are done. Site management, scanning and reports come in later phases. A full README follows in Phase 7.

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
packages/db     Drizzle schema, generated SQL migrations, DB client
packages/shared Domain constants shared by every app
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

## Choices to note

- **Valkey instead of Redis server.** Redis 7.4+ moved to restrictive licences (RSAL/SSPL, then AGPL in 8.0). Valkey is the BSD-licensed fork with the same protocol, and BullMQ and ioredis support it. To use Redis instead, change the image in `docker-compose.yml`.
- **Plugin keys** (Phase 6) are derived from a server master secret with HMAC, so the database stores only a hash of each key and can still verify HMAC-signed reports.
