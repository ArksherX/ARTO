/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_TESSERA_API_BASE?: string;
  readonly VITE_VESTIGIA_API_BASE?: string;
  readonly VITE_VERITYFLUX_API_BASE?: string;
}
interface ImportMeta {
  readonly env: ImportMetaEnv;
}
