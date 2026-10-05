import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import type { ProxyOptions } from "vite";

// Dev proxy: the app calls /api/<service>/... and Vite forwards to the local
// ARTO services (Tessera 8001, Vestigia 8002, VerityFlux 8003). For local dev
// the proxy attaches each service's credential (from the shell env) in the
// header that service expects, so the running app sees live data without
// baking a secret into the browser bundle. Production uses the user's bearer.
interface Auth { header: string; value?: string }
function service(target: string, prefix: string, auth?: Auth): ProxyOptions {
  return {
    target,
    changeOrigin: true,
    rewrite: (p) => p.replace(new RegExp(`^${prefix}`), ""),
    configure: (proxy) => {
      proxy.on("proxyReq", (proxyReq) => {
        if (auth?.value) proxyReq.setHeader(auth.header, auth.value);
      });
    },
  };
}

const vfKey = process.env.VERITYFLUX_API_KEY;
const vesKey = process.env.VESTIGIA_API_KEY;
const tesKey = process.env.TESSERA_API_KEY;

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api/tessera": service(process.env.TESSERA_API_BASE || "http://localhost:8001", "/api/tessera",
        tesKey ? { header: "X-API-Key", value: tesKey } : undefined),
      "/api/vestigia": service(process.env.VESTIGIA_API_BASE || "http://localhost:8002", "/api/vestigia",
        vesKey ? { header: "Authorization", value: `Bearer ${vesKey}` } : undefined),
      "/api/verityflux": service(process.env.VERITYFLUX_API_BASE || "http://localhost:8003", "/api/verityflux",
        vfKey ? { header: "X-API-Key", value: vfKey } : undefined),
    },
  },
});
