import { Card, Chip, Kpi, PageHeader, SourceTag } from "../components/ui";
import { useTessera } from "../data/tessera.live";
import { sampleTessera, sampleChain, sampleApprovals, samplePosture } from "../data/tessera";
import { LoadingLine } from "../components/states";

const SEV: Record<string, string> = { crit: "var(--crit)", high: "var(--high)", med: "var(--med)" };

export default function Tessera() {
  const q = useTessera();
  const source = q.data?.source ?? "sample";
  const m = q.data?.data ?? sampleTessera;

  return (
    <>
      <PageHeader
        title="Tessera · Identity & delegation"
        badge={<span className="inline-flex items-center gap-2 rounded-full border border-ok px-3 py-1.5 text-[12.5px] font-semibold text-ok" style={{ background: "color-mix(in srgb, var(--ok) 13%, transparent)" }}>Scope enforcement on</span>}
        sub={<><span>registration auth required</span><SourceTag source={source} /></>}
      />

      <LoadingLine show={q.isPending} />
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <Kpi label="Agents governed" value={Number.isNaN(m.agents) ? "—" : m.agents.toLocaleString()} />
        <Kpi label="Active delegations" value={Number.isNaN(m.delegations) ? "—" : m.delegations.toLocaleString()} />
        <Kpi label="Scope denials · 24h" value={String(m.denied)} tone={m.denied > 0 ? "var(--high)" : undefined} />
        <Kpi label="Registered" value={String(m.registry.length)} meta="in registry" />
      </div>

      {/* delegation chain (sample — no live delegation detail endpoint) */}
      <Card className="mt-4">
        <div className="mb-3 flex items-center justify-between gap-2">
          <div><h3 className="font-display text-sm font-bold">Delegation chain · a-3391</h3><p className="text-[12px] text-muted">Authority narrows down the chain — a child can never hold a scope its parent didn't grant</p></div>
          <SourceTag source="sample" />
        </div>
        <div className="flex items-stretch gap-0 overflow-x-auto pb-2">
          {sampleChain.map((n, i) => (
            <div key={n.name} className="flex items-stretch">
              {i > 0 && <div className="grid shrink-0 place-items-center px-2 text-acc-300">→</div>}
              <div className="min-w-[200px] shrink-0 rounded-[12px] border border-bd bg-surface2 p-3">
                <div className="text-[9.5px] uppercase tracking-wider text-muted2">{n.role}</div>
                <div className="font-display text-[15px] font-bold">{n.name}</div>
                <div className="font-mono text-[11px] text-muted">{n.id}</div>
                <div className="mt-2.5 flex flex-wrap gap-1.5">
                  {n.scopes.map((s) => (
                    <span key={s.s} className="rounded-md border px-1.5 py-0.5 font-mono text-[10px]"
                      style={s.d ? { color: "var(--crit)", borderColor: "var(--crit)", background: "color-mix(in srgb,var(--crit) 13%,transparent)", textDecoration: "line-through" }
                        : s.g ? { color: "var(--acc-300)", borderColor: "var(--acc-line)", background: "var(--acc-soft)" }
                        : { color: "var(--muted)", borderColor: "var(--border)" }}>{s.s}</span>
                  ))}
                </div>
              </div>
            </div>
          ))}
        </div>
        <div className="mt-3 flex items-center gap-2 text-[11.5px] text-muted2"><span style={{ color: "var(--crit)" }}>●</span> <span><b className="text-text">admin.*</b> requested by a-3391 and <b style={{ color: "var(--crit)" }}>denied</b> — exceeds the grant. Logged to Vestigia.</span></div>
      </Card>

      <div className="mt-4 grid gap-4 lg:grid-cols-[1.6fr_1fr]">
        {/* agent registry (live) */}
        <Card>
          <div className="mb-3 flex items-center justify-between gap-2">
            <div><h3 className="font-display text-sm font-bold">Agent registry</h3><p className="text-[12px] text-muted">Registered identities, scopes &amp; token binding</p></div>
            <SourceTag source={source} />
          </div>
          <div className="overflow-x-auto">
            <table className="w-full min-w-[560px] border-collapse text-[12.5px]">
              <thead>
                <tr className="text-left text-[10px] uppercase tracking-wide text-muted2">
                  <th className="border-b border-bd pb-2 pr-2 font-semibold">Agent</th>
                  <th className="border-b border-bd pb-2 pr-2 font-semibold">Scopes</th>
                  <th className="border-b border-bd pb-2 pr-2 font-semibold">Token</th>
                  <th className="border-b border-bd pb-2 pr-2 font-semibold">Trust</th>
                  <th className="border-b border-bd pb-2 font-semibold">Status</th>
                </tr>
              </thead>
              <tbody>
                {m.registry.map((a) => (
                  <tr key={a.id} className="hover:bg-surface2">
                    <td className="border-b border-bdsoft py-2.5 pr-2"><span className="font-mono text-[11.5px] text-acc-300">{a.id}</span><div className="text-[11px] text-muted2">{a.role}</div></td>
                    <td className="max-w-[240px] truncate border-b border-bdsoft py-2.5 pr-2 font-mono text-[10.5px] text-muted">{a.scopes.join(" · ") || "—"}</td>
                    <td className="border-b border-bdsoft py-2.5 pr-2 text-[11.5px]" style={{ color: a.bound ? "var(--muted)" : "var(--high)" }}>{a.bound ? "bound" : "unbound"}</td>
                    <td className="border-b border-bdsoft py-2.5 pr-2 font-mono text-[11.5px]">{Number.isNaN(a.trust) ? "—" : a.trust}</td>
                    <td className="border-b border-bdsoft py-2.5"><Chip sev={a.status === "active" ? "ok" : "med"}>{a.status}</Chip></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>

        {/* approvals + posture (sample) */}
        <div className="flex flex-col gap-4">
          <Card>
            <div className="mb-2 flex items-center justify-between gap-2">
              <div><h3 className="font-display text-sm font-bold">Pending approvals</h3><p className="text-[12px] text-muted">Four-eyes — the requester cannot approve</p></div>
              <SourceTag source="sample" />
            </div>
            {sampleApprovals.map((a) => (
              <div key={a.req} className="border-b border-bdsoft py-2.5 last:border-0">
                <div className="flex items-center justify-between gap-2"><span className="text-[13px] font-semibold">{a.title}</span><span className="rounded-full border px-2 py-[3px] text-[10px] font-semibold uppercase" style={{ color: SEV[a.sev], borderColor: SEV[a.sev], background: `color-mix(in srgb, ${SEV[a.sev]} 13%, transparent)` }}>{a.sev}</span></div>
                <div className="mt-1 font-mono text-[11px] text-muted">{a.req}</div>
                <div className="mt-2 flex gap-2 text-[11px]">
                  <span className="rounded-full border px-2.5 py-1" style={a.a1 ? { color: "var(--ok)", borderColor: "var(--ok)" } : { color: "var(--muted2)", borderColor: "var(--border)" }}>{a.a1 ? "✓ approver 1" : "○ approver 1"}</span>
                  <span className="rounded-full border px-2.5 py-1" style={a.a2 ? { color: "var(--ok)", borderColor: "var(--ok)" } : { color: "var(--muted2)", borderColor: "var(--border)" }}>{a.a2 ? "✓ approver 2" : "○ approver 2"}</span>
                </div>
              </div>
            ))}
          </Card>
          <Card>
            <div className="flex items-center justify-between gap-2"><h3 className="font-display text-sm font-bold">Token security posture</h3><SourceTag source="sample" /></div>
            <div className="mt-3">
              {samplePosture.map((p) => (
                <div key={p.k} className="mb-3">
                  <div className="mb-1 flex items-center justify-between text-[12px]"><span className="text-muted">{p.k}</span><span className="font-mono text-[11.5px]">{p.v}</span></div>
                  <div className="h-1.5 overflow-hidden rounded-full bg-surface2"><span className="block h-full rounded-full bg-acc" style={{ width: `${p.w}%` }} /></div>
                </div>
              ))}
            </div>
          </Card>
        </div>
      </div>
    </>
  );
}
