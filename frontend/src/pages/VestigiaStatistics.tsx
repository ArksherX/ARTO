import { Card, Kpi, PageHeader, SourceTag } from "../components/ui";
import { LoadingLine } from "../components/states";
import { useVestigiaStats, type StatBucket } from "../data/vestigiaStats.live";

function BreakdownBars({ title, items }: { title: string; items: StatBucket[] }) {
  const max = Math.max(1, ...items.map((i) => i.n));
  return (
    <Card>
      <h3 className="font-display text-sm font-bold">{title}</h3>
      <div className="mt-3 flex flex-col gap-2.5">
        {items.length === 0 && <p className="text-[12.5px] text-muted">No data.</p>}
        {items.map((i) => (
          <div key={i.k}>
            <div className="mb-1 flex items-center justify-between text-[12px]">
              <span className="font-mono text-muted">{i.k}</span>
              <span className="font-mono text-[11.5px] text-text">{i.n.toLocaleString()}</span>
            </div>
            <div className="h-1.5 overflow-hidden rounded-full bg-surface2">
              <span className="block h-full rounded-full bg-acc" style={{ width: `${(i.n / max) * 100}%` }} />
            </div>
          </div>
        ))}
      </div>
    </Card>
  );
}

export default function VestigiaStatistics() {
  const q = useVestigiaStats();
  const source = q.data?.source ?? "sample";
  const m = q.data?.data;
  const fmt = (iso: string) => (iso ? iso.replace("T", " ").replace(/\..*/, "").replace("Z", " UTC") : "—");

  return (
    <>
      <PageHeader title="Vestigia · Statistics" sub={<SourceTag source={source} />} />
      <LoadingLine show={q.isPending} />
      {m && (
        <>
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
            <Kpi label="Total events" value={m.totalEvents.toLocaleString()} />
            <Kpi label="First entry" value={fmt(m.firstEntry)} />
            <Kpi label="Last entry" value={fmt(m.lastEntry)} />
          </div>
          <div className="mt-4 grid gap-4 md:grid-cols-2">
            <BreakdownBars title="By action type" items={m.actions} />
            <BreakdownBars title="By status" items={m.status} />
          </div>
        </>
      )}
    </>
  );
}
