import { defineConfig, loadEnv } from 'vite';

// https://vite.dev/config/
export default defineConfig(({ mode }) => {
  // Load .env files from the frontend directory
  const env = loadEnv(mode, process.cwd(), '');

  // Backend URL — override with VITE_BACKEND_URL in .env for non-standard setups
  const backendUrl = env.VITE_BACKEND_URL || 'http://localhost:3000';

  return {
    root: '.',
    server: {
      // Port defaults to 5173; override with VITE_PORT
      port: parseInt(env.VITE_PORT) || 5173,
      proxy: {
        '/api': {
          target:      backendUrl,
          changeOrigin: true,
        },
      },
    },
    build: {
      outDir: 'dist',
    },
  };
});
