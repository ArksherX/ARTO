import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import type { ProxyOptions } from "vite";

// Dev proxy: the app calls /api/<service>/... and Vite forwards to the local
// ARTO services, so the browser never makes a cross-origin request in dev.
// Ports: Tessera 8001, Vestigia 8002, VerityFlux 8003.
//
// For local dev convenience the proxy attaches each service's API key (from the
// shell env) as X-API-Key, so the running app sees live data without baking a
// secret into the browser bundle. In production the browser instead sends the
// signed-in user's bearer token; nothing here ships to the client.
function service(target: string, prefix: string, apiKey?: string): ProxyOptions {
  return {
    target,
    changeOrigin: true,
    rewrite: (p) => p.replace(new RegExp(`^${prefix}`), ""),
    configure: (proxy) => {
      proxy.on("proxyReq", (proxyReq) => {
        if (apiKey) proxyReq.setHeader("X-API-Key", apiKey);
      });
    },
  };
}

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api/tessera": service(
        process.env.TESSERA_API_BASE || "http://localhost:8001",
        "/api/tessera",
        process.env.TESSERA_API_KEY,
      ),
      "/api/vestigia": service(
        process.env.VESTIGIA_API_BASE || "http://localhost:8002",
        "/api/vestigia",
        process.env.VESTIGIA_API_KEY,
      ),
      "/api/verityflux": service(
        process.env.VERITYFLUX_API_BASE || "http://localhost:8003",
        "/api/verityflux",
        process.env.VERITYFLUX_API_KEY,
      ),
    },
  },
});
