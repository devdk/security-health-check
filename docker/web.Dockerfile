# syntax=docker/dockerfile:1
ARG NODE_IMAGE=node:26-alpine

FROM ${NODE_IMAGE} AS build
WORKDIR /app
COPY package.json package-lock.json ./
COPY packages/shared/package.json packages/shared/
COPY packages/config/package.json packages/config/
COPY packages/db/package.json packages/db/
COPY packages/net/package.json packages/net/
COPY packages/core/package.json packages/core/
COPY packages/ontology/package.json packages/ontology/
COPY packages/scanner/package.json packages/scanner/
COPY packages/intel/package.json packages/intel/
COPY packages/report/package.json packages/report/
COPY packages/companion/package.json packages/companion/
COPY apps/api/package.json apps/api/
COPY apps/worker/package.json apps/worker/
COPY apps/web/package.json apps/web/
RUN npm ci --no-audit --no-fund
COPY tsconfig.base.json ./
COPY packages/shared ./packages/shared
COPY apps/web ./apps/web
RUN npm run build -w @shc/web

# The companion plugin as a download: the dashboard serves it at /downloads/shc-companion.zip.
FROM alpine:3 AS plugin-zip
RUN apk add --no-cache zip
WORKDIR /src
COPY plugin/shc-companion ./shc-companion
RUN mkdir /out && zip -r -X /out/shc-companion.zip shc-companion

# Unprivileged nginx (listens on 8080, runs as a non-root user).
FROM nginxinc/nginx-unprivileged:stable-alpine AS runtime
COPY docker/nginx.conf /etc/nginx/conf.d/default.conf
COPY docker/security-headers.conf /etc/nginx/snippets/security-headers.conf
COPY --from=build /app/apps/web/dist /usr/share/nginx/html
COPY --from=plugin-zip /out/shc-companion.zip /usr/share/nginx/html/downloads/shc-companion.zip
EXPOSE 8080
