#!/usr/bin/env node
/**
 * Bundles a Node service with esbuild.
 *
 * Our own workspace packages (@shc/*) are inlined because they ship TypeScript source.
 * Every third-party package stays external and is loaded from node_modules at runtime,
 * which keeps native modules (argon2) and optional requires (pg-native) working.
 *
 * Usage: node scripts/build-app.mjs --outdir dist src/main.ts other/entry.ts=name
 */
import { build } from 'esbuild';
import path from 'node:path';

const args = process.argv.slice(2);
let outdir = 'dist';
const entryPoints = [];

for (let i = 0; i < args.length; i++) {
  const arg = args[i];
  if (arg === '--outdir') {
    outdir = args[++i];
    continue;
  }
  const [input, name] = arg.split('=');
  entryPoints.push({ in: input, out: name ?? path.basename(input).replace(/\.[cm]?tsx?$/, '') });
}

if (entryPoints.length === 0) {
  console.error('No entry points given.');
  process.exit(1);
}

const externaliseThirdParty = {
  name: 'externalise-third-party',
  setup(b) {
    b.onResolve({ filter: /^[^./]/ }, (resolveArgs) => {
      if (resolveArgs.path.startsWith('@shc/')) return undefined; // bundle our own source
      return { path: resolveArgs.path, external: true };
    });
  },
};

await build({
  entryPoints,
  outdir,
  bundle: true,
  platform: 'node',
  format: 'esm',
  target: 'node22',
  sourcemap: 'linked',
  logLevel: 'info',
  plugins: [externaliseThirdParty],
});
