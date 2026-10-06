import { Card, Kpi, PageHeader, SourceTag } from "../components/ui";
import { LoadingLine } from "../components/states";
import { useSoc } from "../data/soc.live";

const THREAT_TONE: Record<string, string> = {
  green: "var(--ok)", low: "var(--ok)", medium: "var(--med)", high: "var(--high)",
  critical: "var(--crit)", red: "var(--crit)",
};

export default function VerityFluxSOC() {
  const q = useSoc();
  const source = q.data?.source ?? "sample";
  const m = q.data?.data;
  const tone = m ? THREAT_TONE[m.threat.toLowerCase()] ?? "var(--muted)" : "var(--muted)";

  return (
    <>
      <PageHeader
        title="SOC Command Center"
        badge={m && (
          <span className="inline-flex items-center gap-2 rounded-full border px-3 py-1.5 text-[12.5px] font-semibold uppercase"
            style={{ color: tone, borderColor: tone, background: `color-mix(in srgb, ${tone} 13%, transparent)` }}>
            ● {m.threat}
          </span>
        )}
        sub={<SourceTag source={source} />}
      />
      <LoadingLine show={q.isPending} />
      {m && (
        <>
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
            <Kpi label="Open incidents" value={String(m.incidentsOpen)} tone={m.incidentsOpen > 0 ? "var(--crit)" : undefined} meta={`${m.incidentsTotal} total`} />
            <Kpi label="SLA compliance" value={`${m.slaCompliance}%`} tone={m.slaCompliance >= 99 ? "var(--ok)" : "var(--high)"} meta={`${m.slaBreaches} breaches`} />
            <Kpi label="Events · 24h" value={m.eventsTotal.toLocaleString()} meta={`${m.blocked} blocked`} />
            <Kpi label="Blocked" value={String(m.blocked)} tone={m.blocked > 0 ? "var(--crit)" : undefined} />
            <Kpi label="Alerts" value={String(m.alertsTotal)} meta={`${m.alertsNew} new`} />
            <Kpi label="Agents healthy" value={`${m.agentsHealthy}/${m.agentsTotal}`} tone={m.agentsTotal && m.agentsHealthy < m.agentsTotal ? "var(--high)" : "var(--ok)"} />
          </div>
          <Card className="mt-4">
            <h3 className="font-display text-sm font-bold">Operational readiness</h3>
            <p className="mt-2 max-w-[70ch] text-[13px] text-muted">
              Threat level <b style={{ color: tone }}>{m.threat}</b>. Incidents, alerts and agent
              health aggregate the VerityFlux SOC surface; drill into Incidents and Agent
              Monitoring for detail.
            </p>
          </Card>
        </>
      )}
    </>
  );
}
