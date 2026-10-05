import { Card, Kpi, PageHeader, SourceTag } from "../components/ui";
import { useVestigia } from "../data/vestigia.live";
import { sampleVestigia } from "../data/vestigia";

export default function Vestigia() {
  const q = useVestigia();
  const source = q.data?.source ?? "sample";
  const m = q.data?.data ?? sampleVestigia;
  const valid = m.integrity.valid;
  const verifiedTone = valid === false ? "var(--crit)" : "var(--ok)";
  const verifiedLabel = valid === undefined ? "Unknown" : valid ? "Verified" : "Integrity check failed";

  return (
    <>
      <PageHeader
        title="Vestigia · Audit ledger"
        badge={
          <span className="inline-flex items-center gap-2 rounded-full border px-3 py-1.5 text-[12.5px] font-semibold"
            style={{ color: verifiedTone, borderColor: verifiedTone, background: `color-mix(in srgb, ${verifiedTone} 13%, transparent)` }}>
            {valid === false ? "Integrity failed" : "Integrity verified"}
          </span>
        }
        sub={<><span>append-only · hash-chained</span><SourceTag source={source} /></>}
      />

      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <Kpi label="Ledger integrity" value={verifiedLabel} tone={verifiedTone} meta={valid === false ? `${m.integrity.issues.length} issue(s)` : "0 breaks"} />
        <Kpi label="Chain entries" value={Number.isNaN(m.integrity.totalEntries) ? "—" : m.integrity.totalEntries.toLocaleString()} meta="sealed + open" />
        <Kpi label="Total events" value={Number.isNaN(m.totalEvents) ? "—" : m.totalEvents.toLocaleString()} />
        <Kpi label="Witness" value="on" tone="var(--ok)" meta="Merkle" />
      </div>

      {/* hash chain from recent events */}
      <Card className="mt-4">
        <div className="mb-3 flex items-center justify-between gap-2">
          <div>
            <h3 className="font-display text-sm font-bold">Hash chain</h3>
            <p className="text-[12px] text-muted">Each entry seals the prior hash — a modified entry breaks the chain and is detected</p>
          </div>
          <SourceTag source={source} />
        </div>
        <div className="flex items-stretch gap-0 overflow-x-auto pb-2">
          {m.events.map((e, i) => (
            <div key={e.seq || i} className="flex items-stretch">
              {i > 0 && <div className="grid shrink-0 place-items-center px-1 text-ok">→</div>}
              <div className="min-w-[150px] shrink-0 rounded-[11px] border border-bd bg-surface2 p-3"
                style={e.status === "WARNING" ? { borderColor: "var(--high)" } : { borderColor: "var(--ok)" }}>
                <div className="font-mono text-[11px] font-bold">{e.seq.replace("event_", "#")}</div>
                <div className="mt-2 font-mono text-[11px] text-acc-300">{e.hash}</div>
                <div className="font-mono text-[9.5px] text-muted2">prev {e.prev}</div>
                <div className="mt-2 text-[10.5px] text-muted">{e.time}</div>
              </div>
            </div>
          ))}
        </div>
      </Card>

      <div className="mt-4 grid gap-4 lg:grid-cols-[1.6fr_1fr]">
        {/* event ledger */}
        <Card>
          <div className="mb-3 flex items-center justify-between gap-2">
            <div><h3 className="font-display text-sm font-bold">Event ledger</h3><p className="text-[12px] text-muted">Immutable, hash-chained — newest first</p></div>
            <SourceTag source={source} />
          </div>
          <div className="overflow-x-auto">
            <table className="w-full min-w-[560px] border-collapse text-[12.5px]">
              <thead>
                <tr className="text-left text-[10px] uppercase tracking-wide text-muted2">
                  <th className="border-b border-bd pb-2 pr-2 font-semibold">Seq</th>
                  <th className="border-b border-bd pb-2 pr-2 font-semibold">Time</th>
                  <th className="border-b border-bd pb-2 pr-2 font-semibold">Source</th>
                  <th className="border-b border-bd pb-2 pr-2 font-semibold">Event</th>
                  <th className="border-b border-bd pb-2 pr-2 font-semibold">Hash</th>
                  <th className="border-b border-bd pb-2 font-semibold">Status</th>
                </tr>
              </thead>
              <tbody>
                {m.events.map((e, i) => (
                  <tr key={e.seq || i} className="hover:bg-surface2">
                    <td className="border-b border-bdsoft py-2.5 pr-2 font-mono text-[11px] text-muted">{e.seq.replace("event_", "#")}</td>
                    <td className="border-b border-bdsoft py-2.5 pr-2 font-mono text-[11px] text-muted">{e.time}</td>
                    <td className="border-b border-bdsoft py-2.5 pr-2 text-[10.5px] uppercase tracking-wide text-muted2">{e.source}</td>
                    <td className="border-b border-bdsoft py-2.5 pr-2"><span className="font-mono text-[11.5px]">{e.event}</span><div className="text-[10.5px] text-muted2">{e.summary}</div></td>
                    <td className="border-b border-bdsoft py-2.5 pr-2 font-mono text-[11px] text-acc-300">{e.hash}</td>
                    <td className="border-b border-bdsoft py-2.5 text-[11px]" style={{ color: e.status === "WARNING" ? "var(--high)" : "var(--ok)" }}>{e.status}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>

        {/* integrity panel */}
        <Card>
          <div className="flex items-center justify-between gap-2">
            <h3 className="font-display text-sm font-bold">Integrity</h3>
            <SourceTag source={source} />
          </div>
          <div className="mt-3 flex items-center gap-3">
            <div className="font-display text-xl font-extrabold" style={{ color: verifiedTone }}>{verifiedLabel}</div>
          </div>
          <div className="text-[12px] text-muted">{Number.isNaN(m.integrity.totalEntries) ? "" : `${m.integrity.totalEntries} entries checked`}</div>
          {m.integrity.issues.length > 0 ? (
            <div className="mt-3 flex flex-col gap-2">
              {m.integrity.issues.map((iss, i) => (
                <div key={i} className="rounded-[9px] border px-3 py-2.5 text-[12px]" style={{ background: "color-mix(in srgb, var(--crit) 12%, transparent)", borderColor: "var(--crit)" }}>
                  <div className="flex items-center gap-2 font-semibold" style={{ color: "var(--crit)" }}>
                    <span className="h-2 w-2 rounded-full bg-crit" />{iss.severity} · {iss.type}{!Number.isNaN(iss.entry ?? NaN) ? ` · entry ${iss.entry}` : ""}
                  </div>
                  <div className="mt-1 text-muted">{iss.description}</div>
                </div>
              ))}
            </div>
          ) : (
            <div className="mt-3 rounded-[9px] border px-3 py-2.5 text-[12px] text-ok" style={{ background: "var(--ok-soft, color-mix(in srgb, var(--ok) 12%, transparent))", borderColor: "var(--ok)" }}>
              No integrity issues · Merkle witness on, external anchor off-box.
            </div>
          )}
        </Card>
      </div>
    </>
  );
}
