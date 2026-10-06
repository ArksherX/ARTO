import { Card, PageHeader, SourceTag } from "../components/ui";
import { LoadingLine } from "../components/states";
import { useVestigiaEvents } from "../data/vestigiaViews.live";

export default function VestigiaAudit() {
  const q = useVestigiaEvents(25);
  const source = q.data?.source ?? "sample";
  const rows = q.data?.data ?? [];

  return (
    <>
      <PageHeader title="Vestigia · Audit Trail" sub={<><span>append-only · hash-chained</span><SourceTag source={source} /></>} />
      <LoadingLine show={q.isPending} />
      <Card>
        <div className="overflow-x-auto">
          <table className="w-full min-w-[620px] border-collapse text-[12.5px]">
            <thead>
              <tr className="text-left text-[10px] uppercase tracking-wide text-muted2">
                <th className="border-b border-bd pb-2 pr-2 font-semibold">Seq</th>
                <th className="border-b border-bd pb-2 pr-2 font-semibold">Time</th>
                <th className="border-b border-bd pb-2 pr-2 font-semibold">Actor</th>
                <th className="border-b border-bd pb-2 pr-2 font-semibold">Action</th>
                <th className="border-b border-bd pb-2 pr-2 font-semibold">Summary</th>
                <th className="border-b border-bd pb-2 pr-2 font-semibold">Hash</th>
                <th className="border-b border-bd pb-2 font-semibold">Status</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((e, i) => (
                <tr key={e.seq || i} className="hover:bg-surface2">
                  <td className="border-b border-bdsoft py-2.5 pr-2 font-mono text-[11px] text-muted">{e.seq.replace("event_", "#")}</td>
                  <td className="border-b border-bdsoft py-2.5 pr-2 font-mono text-[11px] text-muted">{e.time}</td>
                  <td className="border-b border-bdsoft py-2.5 pr-2 text-[11px] text-muted2">{e.source}</td>
                  <td className="border-b border-bdsoft py-2.5 pr-2 font-mono text-[11.5px]">{e.event}</td>
                  <td className="max-w-[260px] truncate border-b border-bdsoft py-2.5 pr-2 text-[11.5px] text-muted">{e.summary}</td>
                  <td className="border-b border-bdsoft py-2.5 pr-2 font-mono text-[11px] text-acc-300">{e.hash}</td>
                  <td className="border-b border-bdsoft py-2.5 text-[11px]" style={{ color: e.status === "WARNING" ? "var(--high)" : "var(--ok)" }}>{e.status}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </>
  );
}
