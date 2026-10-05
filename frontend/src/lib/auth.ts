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
