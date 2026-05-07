import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  base: '/docs/admin-app/',
  // Resolve TS source before any compiled .js sibling. Vite's default
  // puts .js first, which means a stray emitted .js (e.g. from a stale
  // `tsc -b`) silently shadows the .tsx source and edits no-op until
  // someone notices builds aren't reflecting code changes. Cost a full
  // diagnostic session before this was caught.
  resolve: {
    extensions: ['.tsx', '.ts', '.jsx', '.js', '.mjs', '.json'],
  },
  build: {
    outDir: '../docs/admin-app',
    emptyOutDir: true,
  },
})
