import { useState, type ReactNode } from "react";
import { NavLink, useNavigate } from "react-router-dom";
import { getTheme, applyTheme, type Theme } from "../lib/theme";
import { isAuthed, clearToken, requireLogin } from "../lib/auth";
import { topNav as TABS } from "../lib/nav";

export default function AppShell({ children }: { children: ReactNode }) {
  const [theme, setTheme] = useState<Theme>(getTheme());
  const nav = useNavigate();
  const toggle = () => {
    const next: Theme = theme === "dark" ? "light" : "dark";
    setTheme(next);
    applyTheme(next);
  };
  const logout = () => {
    clearToken();
    nav("/login", { replace: true });
  };
  const showLogout = requireLogin || isAuthed();

  return (
    <div className="min-h-full">
      <header className="sticky top-0 z-20 flex flex-wrap items-center gap-x-5 gap-y-2 border-b border-bd bg-surface px-5 py-3">
        <span className="flex shrink-0 items-center gap-2.5 font-display text-[17px] font-extrabold">
          <span className="h-[22px] w-[22px] rounded-[7px]" style={{ background: "linear-gradient(145deg,var(--acc-300),var(--acc-600))", boxShadow: "0 0 0 4px var(--acc-soft)" }} />
          ARTO
        </span>
        <nav className="flex gap-1 overflow-x-auto" aria-label="Primary">
          {TABS.map((t) => (
            <NavLink
              key={t.to}
              to={t.to}
              end={t.end}
              className={({ isActive }) =>
                "shrink-0 rounded-lg px-3 py-1.5 text-[13.5px] font-medium transition-colors " +
                (isActive ? "text-text bg-acc-soft ring-1 ring-inset ring-acc-line" : "text-muted hover:text-text hover:bg-surface2")
              }
            >
              {t.label}
            </NavLink>
          ))}
        </nav>
        <div className="ml-auto flex shrink-0 items-center gap-3">
          <button
            onClick={toggle}
            aria-label="Toggle light and dark theme"
            className="grid h-[34px] w-[34px] place-items-center rounded-[9px] border border-bd bg-surface2 text-muted hover:text-text"
          >
            {theme === "dark" ? "☾" : "☀"}
          </button>
          {showLogout ? (
            <button onClick={logout} className="rounded-[9px] border border-bd bg-surface2 px-3 py-1.5 text-[12.5px] text-muted hover:border-acc hover:text-acc-300">
              Sign out
            </button>
          ) : (
            <span className="grid h-[34px] w-[34px] place-items-center rounded-full font-display text-xs font-bold text-white" style={{ background: "linear-gradient(145deg,var(--acc-300),var(--acc-700))" }}>
              MO
            </span>
          )}
        </div>
      </header>
      <main className="mx-auto max-w-[1240px] px-5 pb-20 pt-6">{children}</main>
    </div>
  );
}
