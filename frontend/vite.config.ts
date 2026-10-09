/// <reference types="vitest/config" />
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
      },
      '/health': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
      },
      '/scan': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
      },
      '/remediate': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
      },
      '/remediation': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
      },
      '/probes': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
      },
      '/ingest': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
      },
    },
  },
  test: {
    globals: true,
    environment: 'jsdom',
    setupFiles: './src/setupTests.ts',
  },
})
