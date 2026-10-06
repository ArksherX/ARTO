// Typed API clients, one per ARTO service, generated from the committed
// OpenAPI specs (docs/openapi/*.json). Run `pnpm gen:api` to (re)generate the
// schema types under src/lib/schema/ before building.
//
// In dev, base URLs point at the Vite proxy (/api/<service>) so there is no
// cross-origin request; in production set VITE_*_API_BASE to the deployed hosts.
import createClient, { type Middleware } from "openapi-fetch";
import type { paths as TesseraPaths } from "./schema/tessera";
import type { paths as VestigiaPaths } from "./schema/vestigia";
import type { paths as VerityfluxPaths } from "./schema/verityflux";
import { getToken } from "./auth";

// Attach the signed-in user's bearer token when one is present. In dev the
// proxy also injects a service key; in production this is the real credential.
const authMiddleware: Middleware = {
  onRequest({ request }) {
    const t = getToken();
    if (t) request.headers.set("Authorization", `Bearer ${t}`);
    return request;
  },
};

export const tessera = createClient<TesseraPaths>({
  baseUrl: import.meta.env.VITE_TESSERA_API_BASE ?? "/api/tessera",
});
export const vestigia = createClient<VestigiaPaths>({
  baseUrl: import.meta.env.VITE_VESTIGIA_API_BASE ?? "/api/vestigia",
});
export const verityflux = createClient<VerityfluxPaths>({
  baseUrl: import.meta.env.VITE_VERITYFLUX_API_BASE ?? "/api/verityflux",
});

tessera.use(authMiddleware);
vestigia.use(authMiddleware);
verityflux.use(authMiddleware);
