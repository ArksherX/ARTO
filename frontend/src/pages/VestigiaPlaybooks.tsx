import { Card, PageHeader, SourceTag } from "../components/ui";
import { LoadingLine } from "../components/states";
import { usePlaybooks } from "../data/vestigiaViews.live";

export default function VestigiaPlaybooks() {
  const q = usePlaybooks();
  const source = q.data?.source ?? "sample";
  const rows = q.data?.data ?? [];

  return (
    <>
      <PageHeader title="Vestigia · Playbooks" sub={<><span>incident response</span><SourceTag source={source} /></>} />
      <LoadingLine show={q.isPending} />
      <div className="grid gap-4 md:grid-cols-2">
        {rows.map((p, i) => (
          <Card key={p.name || i}>
            <div className="flex items-center justify-between gap-2">
              <h3 className="font-display text-sm font-bold">{p.name}</h3>
              <span className="rounded-md border border-bd px-2 py-0.5 font-mono text-[10.5px] text-muted2">{p.trigger}</span>
            </div>
            <p className="mt-2 text-[12.5px] text-muted">{p.description}</p>
            {p.steps.length > 0 && (
              <ol className="mt-3 flex flex-col gap-1.5">
                {p.steps.map((s, j) => (
                  <li key={j} className="flex gap-2 text-[12.5px]">
                    <span className="font-mono text-acc-300">{j + 1}.</span>
                    <span>{s}</span>
                  </li>
                ))}
              </ol>
            )}
          </Card>
        ))}
      </div>
    </>
  );
}
