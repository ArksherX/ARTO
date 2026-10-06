/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_TESSERA_API_BASE?: string;
  readonly VITE_VESTIGIA_API_BASE?: string;
  readonly VITE_VERITYFLUX_API_BASE?: string;
  readonly VITE_REQUIRE_LOGIN?: string;
  readonly VITE_OIDC_ISSUER?: string;
  readonly VITE_OIDC_CLIENT_ID?: string;
  readonly VITE_OIDC_REDIRECT_URI?: string;
}
interface ImportMeta {
  readonly env: ImportMetaEnv;
}
