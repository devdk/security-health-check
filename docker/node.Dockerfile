# syntax=docker/dockerfile:1
# Builds the API or the worker. Usage: docker build --build-arg APP=api -f docker/node.Dockerfile .
ARG NODE_IMAGE=node:26-alpine

# ---- install all dependencies (cached on lockfile + manifests) ----
FROM ${NODE_IMAGE} AS deps
WORKDIR /app
COPY package.json package-lock.json ./
COPY packages/shared/package.json packages/shared/
COPY packages/config/package.json packages/config/
COPY packages/db/package.json packages/db/
COPY apps/api/package.json apps/api/
COPY apps/worker/package.json apps/worker/
COPY apps/web/package.json apps/web/
RUN npm ci --no-audit --no-fund

# ---- bundle the service ----
FROM deps AS build
ARG APP
COPY tsconfig.base.json ./
COPY scripts ./scripts
COPY packages ./packages
COPY apps/${APP} ./apps/${APP}
RUN npm run build -w @shc/${APP}

# ---- production dependencies only ----
FROM ${NODE_IMAGE} AS prod-deps
WORKDIR /app
COPY --from=deps /app/package.json /app/package-lock.json ./
COPY --from=deps /app/packages ./packages
COPY --from=deps /app/apps ./apps
RUN npm ci --omit=dev --no-audit --no-fund && npm cache clean --force

# ---- runtime ----
FROM ${NODE_IMAGE} AS runtime
ARG APP
ENV NODE_ENV=production \
    MIGRATIONS_DIR=/app/migrations
WORKDIR /app
COPY --from=prod-deps /app/node_modules ./node_modules
COPY --from=build /app/apps/${APP}/dist ./apps/${APP}/dist
COPY packages/db/migrations ./migrations
WORKDIR /app/apps/${APP}
USER node
CMD ["node", "--enable-source-maps", "dist/main.js"]
