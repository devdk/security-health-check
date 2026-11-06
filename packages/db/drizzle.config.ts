import { defineConfig } from 'drizzle-kit';

// Only used by `drizzle-kit generate`, which diffs the schema against existing
// migrations and does not connect to a database.
export default defineConfig({
  dialect: 'postgresql',
  schema: './src/schema.ts',
  out: './migrations',
  strict: true,
  verbose: true,
});
