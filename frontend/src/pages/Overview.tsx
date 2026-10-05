import { Link } from "react-router-dom";
import { Card, Chip, Kpi, PageHeader, SampleBadge } from "../components/ui";
import { overviewKpis, pillars } from "../data/sample";

export default function Overview() {
  return (
    <>
      <PageHeader
        title="Security posture"
        badge={
          <span className="inline-flex items-center gap-2 rounded-full border border-high px-3 py-1.5 text-[12.5px] font-semibold text-high" style={{ background: "color-mix(in srgb, var(--high) 12%, transparent)" }}>
            Attention needed
          </span>
        }
        sub={
          <>
            <span>Acme AI Platform · prod</span>
            <span aria-hidden>·</span>
            <span className="text-ok">● Live</span>
            <SampleBadge />
          </>
        }
      />

      <div className="grid grid-cols-2 gap-4 sm:grid-cols-3">
        {overviewKpis.map((k) => (
          <Kpi key={k.label} label={k.label} value={k.value} meta={k.meta} tone={k.tone} />
        ))}
      </div>

      <div className="mb-2.5 mt-7 text-[12px] uppercase tracking-wider text-muted2">Suite</div>
      <div className="grid gap-4 md:grid-cols-3">
        {pillars.map((p) => (
          <Card key={p.key}>
            <div className="font-display text-base font-bold">{p.name}</div>
            <div className="text-[11.5px] uppercase tracking-wide text-muted2">{p.role}</div>
            <div className="mt-3 flex flex-wrap gap-4">
              {p.stats.map((s) => (
                <div key={s.k}>
                  <div className="font-display text-lg font-bold" style={s.tone ? { color: s.tone } : undefined}>
                    {s.v}
                  </div>
                  <div className="text-[11px] text-muted">{s.k}</div>
                </div>
              ))}
            </div>
            <div className="mt-3.5 flex items-center justify-between border-t border-bdsoft pt-3">
              <Chip sev={p.sev}>{p.sevLabel}</Chip>
              <Link to={`/${p.key}`} className="text-[13px] font-semibold text-acc-300 hover:underline">
                Open {p.name} →
              </Link>
            </div>
          </Card>
        ))}
      </div>

      <p className="mt-6 max-w-[70ch] text-[13px] text-muted">
        Figures above are sample data. Each pillar page is wired to its live API in a later
        increment (see <span className="font-mono text-acc-300">frontend/README.md</span>).
      </p>
    </>
  );
}
