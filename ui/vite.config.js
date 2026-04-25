import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    host: '127.0.0.1',
    port: 3000,
    strictPort: false,
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:5000',
        changeOrigin: true
      },
      '/ws': {
        target: 'ws://127.0.0.1:5000',
        ws: true,
        timeout: 30000,
        proxyTimeout: 30000,
        configure: (proxy, _options) => {
          proxy.on('error', (err, _req, _res) => {
            // Suppress harmless socket reset errors during HMR/Page Reloads
            const codes = ['ECONNRESET', 'ECONNABORTED', 'ETIMEDOUT'];
            if (codes.includes(err.code) || err.message.includes('ECONNABORTED')) {
              return; 
            }
            // Only log genuine errors that aren't socket aborts
            if (!err.message.includes('socket hang up')) {
              console.error('[Vite Proxy Error]:', err);
            }
          });
        }
      }
    }
  }
})
