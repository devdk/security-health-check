import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    projects: ['packages/shared', 'packages/config', 'packages/ontology', 'packages/net', 'packages/scanner', 'apps/api', 'apps/worker'],
  },
});
