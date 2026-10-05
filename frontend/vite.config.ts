import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Dev proxy: the app calls /api/<service>/... and Vite forwards to the local
// ARTO services, so the browser never makes a cross-origin request in dev.
// Ports: Tessera 8001, Vestigia 8002, VerityFlux 8003.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api/tessera": {
        target: process.env.TESSERA_API_BASE || "http://localhost:8001",
        changeOrigin: true,
        rewrite: (p) => p.replace(/^\/api\/tessera/, ""),
      },
      "/api/vestigia": {
        target: process.env.VESTIGIA_API_BASE || "http://localhost:8002",
        changeOrigin: true,
        rewrite: (p) => p.replace(/^\/api\/vestigia/, ""),
      },
      "/api/verityflux": {
        target: process.env.VERITYFLUX_API_BASE || "http://localhost:8003",
        changeOrigin: true,
        rewrite: (p) => p.replace(/^\/api\/verityflux/, ""),
      },
    },
  },
});
