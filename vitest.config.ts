import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    projects: ['packages/config', 'apps/api'],
  },
});
