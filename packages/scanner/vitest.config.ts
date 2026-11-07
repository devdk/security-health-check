import { existsSync } from 'node:fs';
import path from 'node:path';
import { defineConfig } from 'vitest/config';

// The Redis rate-limiter test uses TEST_REDIS_URL when available (skipped otherwise).
const envFile = path.resolve(import.meta.dirname, '../../.env');
if (existsSync(envFile)) process.loadEnvFile(envFile);

export default defineConfig({
  test: { name: 'scanner' },
});
