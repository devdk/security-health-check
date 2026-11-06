#!/usr/bin/env node
// Creates .env from .env.example with freshly generated passwords.
// Refuses to overwrite an existing .env unless --force is passed.
import { randomBytes } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const target = path.join(root, '.env');
const force = process.argv.includes('--force');

if (existsSync(target) && !force) {
  console.log('.env already exists; leaving it alone. Use --force to regenerate (this changes the DB password).');
  process.exit(0);
}

// Hex keeps the values safe inside connection URLs.
const secret = () => randomBytes(24).toString('hex');
const values = { POSTGRES_PASSWORD: secret(), REDIS_PASSWORD: secret() };

const template = readFileSync(path.join(root, '.env.example'), 'utf8');
const output = template.replace(/\{\{(\w+)\}\}/g, (match, name) => values[name] ?? match);

writeFileSync(target, output, { mode: 0o600 });
console.log('Wrote .env with new random passwords.');
