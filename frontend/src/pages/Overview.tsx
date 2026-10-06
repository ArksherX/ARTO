import { Link } from "react-router-dom";
import { Card, Chip, Kpi, PageHeader, SampleBadge, SourceTag } from "../components/ui";
import { overviewKpis as sampleKpis, pillars as samplePillars } from "../data/sample";
import { useOverview } from "../data/overview.live";
import { LoadingLine } from "../components/states";

const TONE: Record<string, string> = { ok: "var(--ok)", high: "var(--high)", crit: "var(--crit)" };

export default function Overview() {
  const q = useOverview();
  const source = q.data?.source ?? "sample";
  const model = q.data?.data ?? { posture: { title: "Attention needed", detail: "", tone: "high" as const }, kpis: sampleKpis, pillars: samplePillars };
  const postureTone = TONE[model.posture.tone] ?? "var(--high)";

  return (
    <>
      <PageHeader
        title="Security posture"
        badge={
          <span className="inline-flex items-center gap-2 rounded-full border px-3 py-1.5 text-[12.5px] font-semibold" style={{ color: postureTone, borderColor: postureTone, background: `color-mix(in srgb, ${postureTone} 12%, transparent)` }}>
            {model.posture.title}
          </span>
        }
        sub={
          <>
            <span>Acme AI Platform · prod</span>
            <span aria-hidden>·</span>
            {source === "live" ? <span className="text-ok">● Live</span> : <span className="text-muted2">● Sample · API offline</span>}
            {source === "sample" && <SampleBadge />}
          </>
        }
      />

      <LoadingLine show={q.isPending} />
      <div className="mb-3 flex items-center gap-2 text-[12px] text-muted">
        <span>{model.posture.detail}</span>
        <SourceTag source={source} />
      </div>

      <div className="grid grid-cols-2 gap-4 sm:grid-cols-3">
        {model.kpis.map((k) => (
          <Kpi key={k.label} label={k.label} value={k.value} meta={k.meta} tone={k.tone} />
        ))}
      </div>

      <div className="mb-2.5 mt-7 text-[12px] uppercase tracking-wider text-muted2">Suite</div>
      <div className="grid gap-4 md:grid-cols-3">
        {model.pillars.map((p) => (
          <Card key={p.key}>
            <div className="font-display text-base font-bold">{p.name}</div>
            <div className="text-[11.5px] uppercase tracking-wide text-muted2">{p.role}</div>
            <div className="mt-3 flex flex-wrap gap-4">
              {p.stats.map((s) => (
                <div key={s.k}>
                  <div className="font-display text-lg font-bold" style={s.tone ? { color: s.tone } : undefined}>{s.v}</div>
                  <div className="text-[11px] text-muted">{s.k}</div>
                </div>
              ))}
            </div>
            <div className="mt-3.5 flex items-center justify-between border-t border-bdsoft pt-3">
              <Chip sev={p.sev}>{p.sevLabel}</Chip>
              <Link to={`/${p.key}`} className="text-[13px] font-semibold text-acc-300 hover:underline">Open {p.name} →</Link>
            </div>
          </Card>
        ))}
      </div>

      <p className="mt-6 max-w-[70ch] text-[13px] text-muted">
        Live figures come from each service's API (Tessera, Vestigia, VerityFlux). Sections fall
        back to sample data and are tagged when the API is unreachable.
      </p>
    </>
  );
}
