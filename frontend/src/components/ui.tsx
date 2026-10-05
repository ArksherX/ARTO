import type { ReactNode } from "react";

export function Card({ children, className = "" }: { children: ReactNode; className?: string }) {
  return (
    <div className={"rounded-[16px] border border-bd bg-surface p-4 " + className}>{children}</div>
  );
}

export function PageHeader({
  title,
  badge,
  sub,
  actions,
}: {
  title: string;
  badge?: ReactNode;
  sub?: ReactNode;
  actions?: ReactNode;
}) {
  return (
    <div className="mb-5 flex flex-wrap items-center gap-4">
      <div>
        <div className="flex flex-wrap items-center gap-3">
          <h1 className="font-display text-[clamp(22px,3vw,30px)] font-extrabold tracking-tight">
            {title}
          </h1>
          {badge}
        </div>
        {sub && <div className="mt-1.5 flex flex-wrap items-center gap-2.5 text-[13px] text-muted">{sub}</div>}
      </div>
      {actions && <div className="ml-auto flex items-center gap-2.5">{actions}</div>}
    </div>
  );
}

export function Kpi({ label, value, meta, tone }: { label: string; value: ReactNode; meta?: ReactNode; tone?: string }) {
  return (
    <div className="rounded-[10px] border border-bd bg-surface px-3.5 py-3">
      <div className="text-[10.5px] uppercase tracking-wider text-muted2">{label}</div>
      <div className="mt-1.5 font-display text-[23px] font-extrabold tracking-tight" style={tone ? { color: tone } : undefined}>
        {value}
      </div>
      {meta && <div className="mt-1 text-[11.5px] text-muted">{meta}</div>}
    </div>
  );
}

const SEV: Record<string, string> = {
  crit: "var(--crit)",
  high: "var(--high)",
  med: "var(--med)",
  low: "var(--low)",
  ok: "var(--ok)",
  review: "var(--acc-300)",
};

export function Chip({ sev, children }: { sev: keyof typeof SEV; children: ReactNode }) {
  const c = SEV[sev];
  return (
    <span
      className="whitespace-nowrap rounded-full border px-2 py-[3px] text-[10.5px] font-semibold uppercase tracking-wide"
      style={{ color: c, borderColor: c, background: `color-mix(in srgb, ${c} 13%, transparent)` }}
    >
      {children}
    </span>
  );
}

export function SourceTag({ source }: { source: "live" | "sample" }) {
  const live = source === "live";
  return (
    <span
      className="rounded border px-1.5 py-0.5 text-[9.5px] uppercase tracking-wide"
      style={{ color: live ? "var(--ok)" : "var(--muted-2)", borderColor: live ? "var(--ok)" : "var(--border)" }}
    >
      {live ? "live" : "sample"}
    </span>
  );
}

export function SampleBadge() {
  return (
    <span className="rounded-md border border-dashed border-bd px-2 py-[3px] text-[11px] uppercase tracking-wider text-muted2">
      Sample data
    </span>
  );
}
