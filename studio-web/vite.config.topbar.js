import { defineConfig } from 'vite'

// Builds the <crane-app-topbar> Custom Element as a self-registering IIFE
// bundle that both runtimes load identically:
//   - admin React SPA: imports the source TS module so React renders the tag natively
//   - login.html (vanilla): <script src="/docs/shared/crane-topbar.js"> in <head>
// Output is intentionally a single file with no hash — login.html links
// to a stable URL and we don't want cache-bust churn on every admin build.
export default defineConfig({
  // CRITICAL since v1.27.52 (when this bundle started including React):
  // Vite library mode does NOT inline `process.env.NODE_ENV` — it leaves
  // it as a literal so consumers can define it themselves. React's UMD
  // checks process.env.NODE_ENV at runtime, and in a browser there's no
  // `process`, so the bundle throws ReferenceError on first execution
  // and every Custom Element fails to register. Symptom in portal:
  // empty <body></body> after init crashed at first inline script that
  // tried to bind events. Inline it here to "production".
  define: {
    'process.env.NODE_ENV': JSON.stringify('production'),
  },
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
