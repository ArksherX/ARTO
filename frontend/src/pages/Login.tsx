import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { verityflux } from "../lib/api";
import { setToken, oidcEnabled, authorizeUrl } from "../lib/auth";

export default function Login() {
  const nav = useNavigate();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);

  // dev stopgap only (used when OIDC isn't configured)
  async function devSubmit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setErr("");
    try {
      const r = await (verityflux as any).POST("/api/v1/auth/login", { body: { email, password } });
      if (r.error) throw new Error("Login failed");
      const token = r.data?.access_token ?? r.data?.token;
      if (!token) throw new Error("No token returned");
      setToken(String(token));
      nav("/overview", { replace: true });
    } catch (e: any) {
      setErr(e?.message || "Login failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="grid min-h-full place-items-center px-4">
      <div className="w-full max-w-[360px] rounded-[16px] border border-bd bg-surface p-6">
        <div className="mb-5 flex items-center gap-2.5">
          <span className="h-[22px] w-[22px] rounded-[7px]" style={{ background: "linear-gradient(145deg,var(--acc-300),var(--acc-600))" }} />
          <span className="font-display text-[17px] font-extrabold">ARTO</span>
        </div>
        <h1 className="font-display text-xl font-extrabold">Sign in</h1>
        <p className="mt-1 text-[12.5px] text-muted">Access the ARTO console.</p>
        {err && <div className="mt-3 rounded-md border px-3 py-2 text-[12.5px]" style={{ color: "var(--crit)", borderColor: "var(--crit)" }}>{err}</div>}

        {oidcEnabled() ? (
          <button
            type="button"
            onClick={() => { window.location.href = authorizeUrl(); }}
            className="mt-5 w-full rounded-[9px] bg-acc px-4 py-2.5 font-display text-[13.5px] font-bold text-white"
          >
            Sign in with your organization
          </button>
        ) : (
          <form onSubmit={devSubmit}>
            <label className="mt-4 block text-[12px] text-muted">Email
              <input type="email" required value={email} onChange={(e) => setEmail(e.target.value)}
                className="mt-1 w-full rounded-[9px] border border-bd bg-surface2 px-3 py-2 text-[13px] text-text outline-none focus:border-acc" />
            </label>
            <label className="mt-3 block text-[12px] text-muted">Password
              <input type="password" required value={password} onChange={(e) => setPassword(e.target.value)}
                className="mt-1 w-full rounded-[9px] border border-bd bg-surface2 px-3 py-2 text-[13px] text-text outline-none focus:border-acc" />
            </label>
            <button type="submit" disabled={busy}
              className="mt-5 w-full rounded-[9px] bg-acc px-4 py-2.5 font-display text-[13.5px] font-bold text-white disabled:opacity-60">
              {busy ? "Signing in…" : "Sign in (dev)"}
            </button>
            <p className="mt-3 text-[11px] text-muted2">OIDC not configured — using the dev login. Set VITE_OIDC_* to enable SSO.</p>
          </form>
        )}
      </div>
    </div>
  );
}
