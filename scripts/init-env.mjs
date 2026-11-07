#!/usr/bin/env node
// Creates .env from .env.example with freshly generated secrets. If .env already exists,
// only settings that are missing from it are appended; existing values are never changed.
import { randomBytes } from 'node:crypto';
import { appendFileSync, existsSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const target = path.join(root, '.env');

// Hex keeps the values safe inside connection URLs.
const generated = new Map();
const secret = (name) => {
  if (!generated.has(name)) generated.set(name, randomBytes(24).toString('hex'));
  return generated.get(name);
};
const fill = (text) => text.replace(/\{\{(\w+)\}\}/g, (_, name) => secret(name));

const template = readFileSync(path.join(root, '.env.example'), 'utf8');

if (!existsSync(target)) {
  writeFileSync(target, fill(template), { mode: 0o600 });
  console.log('Wrote .env with new random secrets.');
  process.exit(0);
}

const current = readFileSync(target, 'utf8');
const existingKeys = new Set([...current.matchAll(/^([A-Z0-9_]+)=/gm)].map((m) => m[1]));
const missing = template.split(/\r?\n/).filter((line) => {
  const key = /^([A-Z0-9_]+)=/.exec(line)?.[1];
  return key && !existingKeys.has(key);
});

if (missing.length === 0) {
  console.log('.env is up to date; nothing changed.');
} else {
  appendFileSync(target, `${current.endsWith('\n') ? '' : '\n'}\n# Added by setup:env\n${fill(missing.join('\n'))}\n`);
  console.log(`Added ${missing.length} new setting(s) to .env: ${missing.map((l) => l.split('=')[0]).join(', ')}`);
}
