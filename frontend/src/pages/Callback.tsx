import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { verityflux } from "../lib/api";
import { setToken, oidc } from "../lib/auth";

export default function Callback() {
  const nav = useNavigate();
  const [err, setErr] = useState("");
  const ran = useRef(false);

  useEffect(() => {
    if (ran.current) return; // guard StrictMode double-invoke (code is single-use)
    ran.current = true;

    const params = new URLSearchParams(window.location.search);
    const code = params.get("code");
    const state = params.get("state");
    const providerErr = params.get("error_description") || params.get("error");

    let expected = "";
    try {
      expected = sessionStorage.getItem("arto-oidc-state") ?? "";
    } catch {
      /* ignore */
    }

    if (providerErr) { setErr(String(providerErr)); return; }
    if (!code) { setErr("Missing authorization code."); return; }
    if (expected && state && expected !== state) { setErr("State mismatch — please try signing in again."); return; }

    (async () => {
      try {
        const r = await (verityflux as any).POST("/api/v1/auth/oidc/exchange", {
          body: { code, redirect_uri: oidc.redirectUri },
        });
        if (r.error) throw new Error("Exchange failed");
        const token = r.data?.access_token;
        if (!token) throw new Error("No token returned");
        setToken(String(token));
        nav("/overview", { replace: true });
      } catch (e: any) {
        setErr(e?.message || "Sign-in failed");
      }
    })();
  }, [nav]);

  return (
    <div className="grid min-h-full place-items-center px-4 text-center">
      <div>
        {err ? (
          <>
            <p className="font-display text-lg font-bold" style={{ color: "var(--crit)" }}>Sign-in failed</p>
            <p className="mt-2 text-[13px] text-muted">{err}</p>
            <a href="/login" className="mt-4 inline-block text-[13px] font-semibold text-acc-300 hover:underline">Back to sign in</a>
          </>
        ) : (
          <p className="text-[13px] text-muted">Completing sign-in…</p>
        )}
      </div>
    </div>
  );
}
