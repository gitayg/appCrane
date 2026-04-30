import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  base: '/docs/admin-app/',
  build: {
    outDir: '../docs/admin-app',
    emptyOutDir: true,
  },
})
