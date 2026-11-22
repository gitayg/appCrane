import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { devIdentityHeaders } from '../scripts/dev-headers.js';

export default defineConfig({
  // AppCrane serves the app under a sub-path and does not pass APP_BASE_PATH
  // to every build, so the fallback must be relative ('./'), never '/'.
  base: process.env.APP_BASE_PATH || './',
  plugins: [react()],
  server: {
    // Local development only: forward /api to the Express server and sign a
    // test identity with your LOCAL APPCRANE_IDENTITY_SECRET, so the server's
    // verification runs exactly as it does behind AppCrane. Nothing here is
    // part of the production build.
    proxy: {
      '/api': {
        target: 'http://localhost:3000',
        configure: (proxy) => {
          proxy.on('proxyReq', (req) => {
            for (const [k, v] of Object.entries(devIdentityHeaders())) req.setHeader(k, v);
          });
        },
      },
    },
  },
});
