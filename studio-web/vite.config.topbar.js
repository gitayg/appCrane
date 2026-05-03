import { defineConfig } from 'vite'

// Builds the <crane-app-topbar> Custom Element as a self-registering IIFE
// bundle that both runtimes load identically:
//   - admin React SPA: imports the source TS module so React renders the tag natively
//   - login.html (vanilla): <script src="/docs/shared/crane-topbar.js"> in <head>
// Output is intentionally a single file with no hash — login.html links
// to a stable URL and we don't want cache-bust churn on every admin build.
export default defineConfig({
  build: {
    outDir: '../docs/shared',
    emptyOutDir: false,
    lib: {
      entry: 'src/topbar-element/entry.ts',
      name: 'CraneTopbar',
      fileName: () => 'crane-topbar.js',
      formats: ['iife'],
    },
    rollupOptions: {
      output: { extend: true },
    },
  },
})
