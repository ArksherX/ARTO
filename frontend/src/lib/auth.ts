// Browser-held bearer token for production auth. In dev the Vite proxy injects
// each service's key, so login is not required (VITE_REQUIRE_LOGIN defaults
// off); in production set VITE_REQUIRE_LOGIN=true and the app gates on a token.
//
// NOTE (backend dependency): the services currently use different auth schemes
// (VerityFlux X-API-Key/JWT, Vestigia Bearer, Tessera none) and /auth/login
// returns a placeholder token, so end-to-end user login needs a shared JWT or a
// gateway. This layer is the frontend half, ready for that.
const KEY = "arto-token";

export function getToken(): string {
  try {
    return localStorage.getItem(KEY) ?? "";
  } catch {
    return "";
  }
}
export function setToken(t: string): void {
  try {
    localStorage.setItem(KEY, t);
  } catch {
    /* ignore */
  }
}
export function clearToken(): void {
  try {
    localStorage.removeItem(KEY);
  } catch {
    /* ignore */
  }
}
export function isAuthed(): boolean {
  return getToken().length > 0;
}
export const requireLogin = import.meta.env.VITE_REQUIRE_LOGIN === "true";

// OIDC (Auth0) config — all non-secret, safe in the browser. The client secret
// stays server-side (VerityFlux does the code exchange).
export const oidc = {
  domain: (import.meta.env.VITE_OIDC_ISSUER ?? "").replace(/^https?:\/\//, "").replace(/\/$/, ""),
  clientId: import.meta.env.VITE_OIDC_CLIENT_ID ?? "",
  redirectUri:
    import.meta.env.VITE_OIDC_REDIRECT_URI ??
    (typeof window !== "undefined" ? `${window.location.origin}/auth/callback` : ""),
};
export function oidcEnabled(): boolean {
  return Boolean(oidc.domain && oidc.clientId);
}
export function authorizeUrl(): string {
  const state = Math.random().toString(36).slice(2);
  try {
    sessionStorage.setItem("arto-oidc-state", state);
  } catch {
    /* ignore */
  }
  const p = new URLSearchParams({
    response_type: "code",
    client_id: oidc.clientId,
    redirect_uri: oidc.redirectUri,
    scope: "openid profile email",
    state,
  });
  return `https://${oidc.domain}/authorize?${p.toString()}`;
}
