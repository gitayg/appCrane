import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  base: '/docs/studio-app/',
  build: {
    outDir: '../docs/studio-app',
    emptyOutDir: true,
  },
})
