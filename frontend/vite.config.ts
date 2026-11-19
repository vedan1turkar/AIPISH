import { defineConfig, loadEnv } from 'vite'
import react from '@vitejs/plugin-react'

// Dev proxy: /api/* → FastAPI, avoiding browser-side CORS/local-context issues.
// VITE_PROXY_TARGET supports an alternate local port when :8000 is occupied.
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '')
  return {
    plugins: [react()],
    server: {
      port: 5173,
      proxy: {
        '/api': {
          target: env.VITE_PROXY_TARGET || 'http://127.0.0.1:8000',
          changeOrigin: true,
          // Local AI assessments (ML + SHAP + Mistral) can take 1-2+ minutes; never cut
          // a valid request short. LLM_TIMEOUT_SECONDS bounds each model call server-side.
          timeout: 600_000,
          proxyTimeout: 600_000,
        },
      },
    },
  }
})
