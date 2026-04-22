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
        changeOrigin: true,
        configure: (proxy, _options) => {
          proxy.on('error', (err, _req, _res) => {
            // Suppress harmless ECONNABORTED noise during React Fast Refresh (HMR)
            if (err.code !== 'ECONNABORTED') {
              console.log('proxy error', err);
            }
          });
        }
      }
    }
  }
})
