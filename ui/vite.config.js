import { defineConfig, loadEnv } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '');
  const backendPort = env.VITE_BACKEND_PORT || '3000';
  const uiPort = parseInt(env.VITE_PORT || '3000');

  return {
    plugins: [react()],
    server: {
      host: '127.0.0.1',
      port: uiPort,
      strictPort: false,
      proxy: {
        '/api': {
          target: `http://127.0.0.1:${backendPort}`,
          changeOrigin: true
        },
        '/ws': {
          target: `ws://127.0.0.1:${backendPort}`,
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
  }
})
