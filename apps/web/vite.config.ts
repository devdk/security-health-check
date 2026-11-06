import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// In development the dashboard and API share an origin through this proxy, so the
// session cookie stays first-party and no CORS is needed. In Docker, nginx does the same.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    strictPort: true,
    proxy: {
      '/api': { target: process.env.VITE_API_PROXY_TARGET ?? 'http://localhost:3000', changeOrigin: false },
    },
  },
  build: {
    sourcemap: false,
  },
});
