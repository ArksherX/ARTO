import { Card, Chip, PageHeader, SourceTag } from "../components/ui";
import { LoadingLine } from "../components/states";
import { useTessera } from "../data/tessera.live";

export default function TesseraRegistry() {
  const q = useTessera();
  const source = q.data?.source ?? "sample";
  const rows = q.data?.data.registry ?? [];

  return (
    <>
      <PageHeader title="Tessera · Agent Registry" sub={<><span>registered identities</span><SourceTag source={source} /></>} />
      <LoadingLine show={q.isPending} />
      <Card>
        <div className="overflow-x-auto">
          <table className="w-full min-w-[640px] border-collapse text-[12.5px]">
            <thead>
              <tr className="text-left text-[10px] uppercase tracking-wide text-muted2">
                <th className="border-b border-bd pb-2 pr-2 font-semibold">Agent</th>
                <th className="border-b border-bd pb-2 pr-2 font-semibold">Owner</th>
                <th className="border-b border-bd pb-2 pr-2 font-semibold">Scopes</th>
                <th className="border-b border-bd pb-2 pr-2 font-semibold">Token</th>
                <th className="border-b border-bd pb-2 pr-2 font-semibold">Trust</th>
                <th className="border-b border-bd pb-2 font-semibold">Status</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((a) => (
                <tr key={a.id} className="hover:bg-surface2">
                  <td className="border-b border-bdsoft py-2.5 pr-2 font-mono text-[11.5px] text-acc-300">{a.id}</td>
                  <td className="border-b border-bdsoft py-2.5 pr-2 text-[12px] text-muted">{a.role}</td>
                  <td className="max-w-[260px] truncate border-b border-bdsoft py-2.5 pr-2 font-mono text-[10.5px] text-muted">{a.scopes.join(" · ") || "—"}</td>
                  <td className="border-b border-bdsoft py-2.5 pr-2 text-[11.5px]" style={{ color: a.bound ? "var(--muted)" : "var(--high)" }}>{a.bound ? "bound" : "unbound"}</td>
                  <td className="border-b border-bdsoft py-2.5 pr-2 font-mono text-[11.5px]">{Number.isNaN(a.trust) ? "—" : a.trust}</td>
                  <td className="border-b border-bdsoft py-2.5"><Chip sev={a.status === "active" ? "ok" : "med"}>{a.status}</Chip></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </>
  );
}
