import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

/**
 * Configuration Vite — NetWatch Console.
 *
 *  • En développement (`npm run dev`), le serveur Vite tourne sur le port 5173
 *    et relaie transparentement tous les appels `/api/*` vers le backend Flask
 *    (port 5000), y compris le flux temps réel SSE `/api/stream`. Aucun CORS,
 *    aucune configuration réseau à gérer.
 *
 *  • En production (`npm run build`), l'app est compilée dans `dist/`, que Flask
 *    sert directement : le front et l'API partagent la même origine.
 */
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    strictPort: false,
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:5000',
        changeOrigin: true,
        // Indispensable pour le flux SSE : pas de mise en tampon, connexion
        // maintenue ouverte.
        configure: (proxy) => {
          proxy.on('proxyReq', (proxyReq) => {
            proxyReq.setHeader('Accept-Encoding', 'identity');
          });
        },
      },
    },
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    sourcemap: false,
    chunkSizeWarningLimit: 900,
  },
});
