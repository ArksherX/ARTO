import { Card, Chip, Kpi, PageHeader } from "../components/ui";
import {
  vfKpis,
  intentMix,
  reviewQueue,
  obfuscation,
  health,
  trajectory as sampleTrajectory,
  detections as sampleDetections,
  type Detection,
  type Intent,
  type Channel,
  type Action,
  type TrajectoryModel,
} from "../data/verityflux";
import { useLiveStatus, useTrajectory, useDetections, type Source } from "../data/verityflux.live";

const INTENT: Record<Intent, { sev: "crit" | "high" | "med" | "ok" | "review"; label: string }> = {
  exploit: { sev: "crit", label: "Exploit" },
  hostile: { sev: "high", label: "Hostile" },
  probing: { sev: "med", label: "Probing" },
  benign: { sev: "ok", label: "Benign" },
  unknown: { sev: "review", label: "Unknown" },
};

const ACTION_TONE: Record<Action, string> = {
  Blocked: "var(--crit)",
  Flagged: "var(--high)",
  Allowed: "var(--muted)",
  "Requires review": "var(--acc-300)",
};

function scoreColor(s: number): string {
  if (s >= 0.8) return "var(--crit)";
  if (s >= 0.6) return "var(--high)";
  if (s >= 0.4) return "var(--med)";
  return "var(--ok)";
}

function SourceTag({ source }: { source: Source }) {
  const live = source === "live";
  return (
    <span
      className="rounded border px-1.5 py-0.5 text-[9.5px] uppercase tracking-wide"
      style={{
        color: live ? "var(--ok)" : "var(--muted-2)",
        borderColor: live ? "var(--ok)" : "var(--border)",
      }}
    >
      {live ? "live" : "sample"}
    </span>
  );
}

function ScoreBar({ score }: { score: number | null }) {
  if (score === null) return <span className="font-mono text-[11px] text-muted">—</span>;
  const c = scoreColor(score);
  return (
    <span className="flex items-center gap-2">
      <span className="h-1.5 w-[52px] shrink-0 overflow-hidden rounded-full bg-surface2">
        <span className="block h-full rounded-full" style={{ width: `${Math.round(score * 100)}%`, background: c }} />
      </span>
      <span className="font-mono text-[11px] text-muted">{score.toFixed(2)}</span>
    </span>
  );
}

function ChannelTag({ channel }: { channel: Channel }) {
  const risky = channel === "data";
  return (
    <span
      className="rounded border px-1.5 py-0.5 text-[10px] uppercase tracking-wide"
      style={{ color: risky ? "var(--high)" : "var(--muted-2)", borderColor: risky ? "var(--high)" : "var(--border)" }}
    >
      {channel}
    </span>
  );
}

function TrajectoryChart({ t }: { t: TrajectoryModel }) {
  const W = 400, H = 170, padL = 34, padR = 14, padT = 16, padB = 28;
  const n = Math.max(t.points.length - 1, 1);
  const x = (turn: number) => padL + ((turn - 1) / n) * (W - padL - padR);
  const y = (d: number) => padT + (1 - d) * (H - padT - padB);
  const pts = t.points.map((p) => `${x(p.turn).toFixed(1)},${y(p.drift).toFixed(1)}`).join(" ");
  const first = t.points[0], last = t.points[t.points.length - 1];
  const area = `M${pts.split(" ").join(" L")} L${x(last.turn)},${H - padB} L${x(first.turn)},${H - padB} Z`;
  const tp = t.points.find((p) => p.turn === t.turningPoint) ?? last;
  return (
    <svg viewBox={`0 0 ${W} ${H}`} className="mt-3 block w-full" style={{ height: 170 }} role="img"
      aria-label="Drift across turns with elevated/critical thresholds and a turning point">
      {[0.33, 0.66, 1].map((g) => (
        <line key={g} x1={padL} y1={y(g)} x2={W - padR} y2={y(g)} stroke="var(--border-soft)" strokeWidth={1} />
      ))}
      <line x1={padL} y1={y(t.critical)} x2={W - padR} y2={y(t.critical)} stroke="var(--crit)" strokeWidth={1.1} strokeDasharray="4 4" opacity={0.65} />
      <text x={W - padR} y={y(t.critical) - 5} textAnchor="end" fill="var(--crit)" fontFamily="monospace" fontSize={9}>critical</text>
      <line x1={padL} y1={y(t.elevated)} x2={W - padR} y2={y(t.elevated)} stroke="var(--high)" strokeWidth={1.1} strokeDasharray="4 4" opacity={0.5} />
      <text x={W - padR} y={y(t.elevated) - 5} textAnchor="end" fill="var(--high)" fontFamily="monospace" fontSize={9}>elevated</text>
      <path d={area} fill="var(--acc-soft)" />
      <polyline points={pts} fill="none" stroke="var(--acc)" strokeWidth={2.4} strokeLinejoin="round" strokeLinecap="round" />
      <circle cx={x(tp.turn)} cy={y(tp.drift)} r={4.5} fill="var(--acc)" stroke="var(--surface)" strokeWidth={2} />
      <text x={x(tp.turn)} y={y(tp.drift) - 12} textAnchor="middle" fill="var(--acc-300)" fontFamily="monospace" fontSize={9}>turning point · t{tp.turn}</text>
      {[first.turn, tp.turn, last.turn].map((tn) => (
        <text key={tn} x={x(tn)} y={H - 10} textAnchor="middle" fill="var(--muted-2)" fontFamily="monospace" fontSize={9}>t{tn}</text>
      ))}
    </svg>
  );
}

export default function VerityFlux() {
  const status = useLiveStatus();
  const online = status.isSuccess;

  const trajQ = useTrajectory();
  const traj = trajQ.data?.data ?? sampleTrajectory;
  const trajSource: Source = trajQ.data?.source ?? "sample";

  const detQ = useDetections();
  const det: Detection[] = detQ.data?.data ?? sampleDetections;
  const detSource: Source = detQ.data?.source ?? "sample";

  const mixTotal = intentMix.reduce((a, m) => a + m.n, 0);

  return (
    <>
      <PageHeader
        title="VerityFlux · Runtime detection"
        badge={
          <span className="inline-flex items-center gap-2 rounded-full border border-acc-line px-3 py-1.5 text-[12px] font-semibold text-acc-300" style={{ background: "var(--acc-soft)" }}>
            Report-only
          </span>
        }
        sub={
          <>
            {online ? <span className="text-ok">● Live</span> : <span className="text-muted2">● Sample · API offline</span>}
            <span>scorer gpt-4o-mini</span>
          </>
        }
      />

      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
        {vfKpis.map((k) => <Kpi key={k.label} label={k.label} value={k.value} tone={k.tone} />)}
      </div>

      <div className="mt-4 grid gap-4 lg:grid-cols-[1.55fr_1fr]">
        <Card>
          <div className="mb-3 flex flex-wrap items-center justify-between gap-2.5">
            <div>
              <h3 className="font-display text-sm font-bold">Detection stream</h3>
              <p className="text-[12px] text-muted">Per-input verdicts across user, tool, memory &amp; data channels</p>
            </div>
            <SourceTag source={detSource} />
          </div>
          <div className="overflow-x-auto">
            <table className="w-full min-w-[640px] border-collapse text-[12.5px]">
              <thead>
                <tr className="text-left text-[10px] uppercase tracking-wide text-muted2">
                  <th className="border-b border-bd pb-2 pr-2 font-semibold">Time</th>
                  <th className="border-b border-bd pb-2 pr-2 font-semibold">Session</th>
                  <th className="border-b border-bd pb-2 pr-2 font-semibold">Chan</th>
                  <th className="border-b border-bd pb-2 pr-2 font-semibold">Input</th>
                  <th className="border-b border-bd pb-2 pr-2 font-semibold">Intent</th>
                  <th className="border-b border-bd pb-2 pr-2 font-semibold">Hostility</th>
                  <th className="border-b border-bd pb-2 font-semibold">Action</th>
                </tr>
              </thead>
              <tbody>
                {det.map((d, i) => (
                  <tr key={i} className="hover:bg-surface2">
                    <td className="border-b border-bdsoft py-2.5 pr-2 font-mono text-[11.5px] text-muted">{d.time}</td>
                    <td className="border-b border-bdsoft py-2.5 pr-2 font-mono text-[11.5px] text-acc-300">{d.session}</td>
                    <td className="border-b border-bdsoft py-2.5 pr-2"><ChannelTag channel={d.channel} /></td>
                    <td className="max-w-[280px] truncate border-b border-bdsoft py-2.5 pr-2 font-mono text-[11.5px]">
                      {d.input}{d.obf && <span className="ml-1.5 text-[10px] text-acc-300">· {d.obf}</span>}
                    </td>
                    <td className="border-b border-bdsoft py-2.5 pr-2"><Chip sev={INTENT[d.intent].sev}>{INTENT[d.intent].label}</Chip></td>
                    <td className="border-b border-bdsoft py-2.5 pr-2"><ScoreBar score={d.score} /></td>
                    <td className="border-b border-bdsoft py-2.5 text-[11.5px] font-semibold" style={{ color: ACTION_TONE[d.action] }}>{d.action}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>

        <div className="flex flex-col gap-4">
          <Card>
            <div className="flex items-start justify-between gap-2">
              <div>
                <h3 className="font-display text-sm font-bold">Session trajectory · {traj.session}</h3>
                <p className="text-[12px] text-muted">Turn-over-turn decay-delta drift</p>
              </div>
              <SourceTag source={trajSource} />
            </div>
            <div className="mt-3 flex flex-wrap gap-3.5 text-[12px] text-muted">
              <span>agent <b className="font-mono font-normal text-text">{traj.agent}</b></span>
              <span>turns <b className="font-mono font-normal text-text">{traj.points.length}</b></span>
            </div>
            <TrajectoryChart t={traj} />
            <div className="mt-3 flex items-center gap-2.5 rounded-[9px] border px-3 py-2.5 text-[12px]" style={{ background: "color-mix(in srgb, var(--crit) 13%, transparent)", borderColor: "var(--crit)" }}>
              <span className="h-2 w-2 shrink-0 rounded-full bg-crit" />
              <span>A turning point opens an escalation contract (report-only) for dual-control review.</span>
            </div>
          </Card>

          <Card>
            <div className="flex items-start justify-between gap-2">
              <h3 className="font-display text-sm font-bold">Flagged intent mix · 24h</h3>
              <SourceTag source="sample" />
            </div>
            <p className="text-[12px] text-muted">Of {mixTotal} flagged inputs (benign excluded)</p>
            <div className="mt-3 flex h-4 overflow-hidden rounded-md bg-surface2">
              {intentMix.map((m) => <span key={m.k} style={{ width: `${(m.n / mixTotal) * 100}%`, background: m.c }} />)}
            </div>
            <div className="mt-3 grid grid-cols-2 gap-x-3.5 gap-y-1.5 text-[12px] text-muted">
              {intentMix.map((m) => (
                <span key={m.k} className="flex items-center gap-2">
                  <b className="inline-block h-2.5 w-2.5 shrink-0 rounded-sm" style={{ background: m.c }} />
                  {m.k}
                  <span className="ml-auto font-mono text-[11.5px] text-text">{m.n}</span>
                </span>
              ))}
            </div>
          </Card>
        </div>
      </div>

      <div className="mb-2.5 mt-7 text-[11.5px] uppercase tracking-wider text-muted2">Review &amp; detector health</div>
      <div className="grid gap-4 lg:grid-cols-[1.6fr_1fr]">
        <Card>
          <div className="mb-3 flex flex-wrap items-center justify-between gap-2.5">
            <div>
              <h3 className="font-display text-sm font-bold">Needs human review</h3>
              <p className="text-[12px] text-muted">Scorer abstained (fail-closed) — never cleared as benign</p>
            </div>
            <Chip sev="review">{reviewQueue.length} open</Chip>
          </div>
          {reviewQueue.map((r, i) => (
            <div key={i} className="flex items-center gap-2.5 border-b border-bdsoft py-2.5 text-[12.5px] last:border-0">
              <div>
                <div className="text-text">{r.why}</div>
                <div className="font-mono text-[11px] text-muted2">{r.sub}</div>
              </div>
              <span className="ml-auto whitespace-nowrap font-mono text-[11px] text-muted">{r.age}</span>
              <button className="rounded-[7px] border border-bd bg-surface2 px-2.5 py-[5px] text-[11.5px] text-text hover:border-acc hover:text-acc-300">Assign</button>
            </div>
          ))}
        </Card>

        <div className="flex flex-col gap-4">
          <Card>
            <h3 className="font-display text-sm font-bold">Obfuscation defeated · 24h</h3>
            <p className="text-[12px] text-muted">Canonicalized before keyword matching</p>
            <div className="mt-3 grid grid-cols-3 gap-2.5">
              {obfuscation.map((o) => (
                <div key={o.l} className="rounded-[9px] border border-bdsoft bg-surface2 p-2.5">
                  <div className="font-display text-lg font-bold">{o.n}</div>
                  <div className="text-[10.5px] text-muted">{o.l}</div>
                </div>
              ))}
            </div>
          </Card>
          <Card>
            <h3 className="font-display text-sm font-bold">Detector health</h3>
            <div className="mt-3 flex flex-col gap-2 text-[12.5px]">
              {health.map((h) => (
                <div key={h.k} className="flex items-center justify-between">
                  <span className="text-muted">{h.k}</span>
                  <span className="font-mono text-[11.5px]" style={{ color: h.ok ? "var(--ok)" : "var(--text)" }}>{h.v}</span>
                </div>
              ))}
            </div>
          </Card>
        </div>
      </div>
    </>
  );
}
