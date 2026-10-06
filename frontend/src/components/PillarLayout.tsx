import { NavLink, Outlet } from "react-router-dom";
import type { NavItem } from "../lib/nav";

export default function PillarLayout({ nav }: { nav: NavItem[] }) {
  return (
    <div className="grid gap-6 md:grid-cols-[200px_1fr]">
      <nav className="flex gap-1 overflow-x-auto md:flex-col md:overflow-visible" aria-label="Section">
        {nav.map((n) => (
          <NavLink
            key={n.to}
            to={n.to}
            end={n.end}
            className={({ isActive }) =>
              "shrink-0 rounded-lg px-3 py-2 text-[13px] font-medium transition-colors md:shrink " +
              (isActive ? "text-text bg-acc-soft ring-1 ring-inset ring-acc-line" : "text-muted hover:text-text hover:bg-surface2")
            }
          >
            {n.label}
          </NavLink>
        ))}
      </nav>
      <div className="min-w-0">
        <Outlet />
      </div>
    </div>
  );
}
