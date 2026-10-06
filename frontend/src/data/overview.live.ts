// Live data for the Overview posture screen, aggregated across all three
// services via their typed clients. Uses only public endpoints (Tessera/Vestigia
// /health + efficacy; VerityFlux efficacy + sessions — the VerityFlux key is
// attached by the dev proxy). Defensive: falls back to sample when nothing is
// reachable, and fills any missing piece from sample.
import { useQuery } from "@tanstack/react-query";
import { tessera, vestigia, verityflux } from "../lib/api";
import { overviewKpis as sampleKpis, pillars as samplePillars } from "./sample";
import type { Sourced } from "./verityflux.live";

type Sev = "ok" | "high" | "crit" | "med" | "low" | "review";
export interface OverviewModel {
  posture: { title: string; detail: string; tone: Sev };
  kpis: { label: string; value: string; meta?: string; tone?: string }[];
  pillars: {
    key: string; name: string; role: string;
    stats: { v: string; k: string; tone?: string }[];
    sev: Sev; sevLabel: string;
  }[];
}

const SAMPLE: OverviewModel = {
  posture: { title: "Attention needed", detail: "2 escalations open · 1 critical", tone: "high" },
  kpis: sampleKpis,
  pillars: samplePillars,
};

function num(v: unknown, d = 0): number {
  const n = typeof v === "string" ? parseFloat(v) : (v as number);
  return Number.isFinite(n) ? n : d;
}
async function get(client: any, path: string, init?: any): Promise<any> {
  const r = await client.GET(path, init);
  if (r.error) throw r.error;
  return r.data;
}
function val<T>(r: PromiseSettledResult<T>): T | null {
  return r.status === "fulfilled" ? r.value : null;
}

export function useOverview() {
  return useQuery<Sourced<OverviewModel>>({
    queryKey: ["overview"],
    queryFn: async () => {
      const [tHealth, tEff, vHealth, vfEff, vfSessions] = await Promise.allSettled([
        get(tessera, "/health"),
        get(tessera, "/security/efficacy"),
        get(vestigia, "/health"),
        get(verityflux, "/api/v2/efficacy/report"),
        get(verityflux, "/api/v2/sessions"),
      ]);
      const anyLive = [tHealth, tEff, vHealth, vfEff, vfSessions].some((r) => r.status === "fulfilled");
      if (!anyLive) return { source: "sample", data: SAMPLE };

      const th = val(tHealth) as any;
      const teff = val(tEff) as any;
      const vh = val(vHealth) as any;
      const vfe = val(vfEff) as any;
      const vsess = val(vfSessions) as any;

      const agents = num(th?.agents, NaN);
      const denied = num(teff?.denied_total, 0);
      const ledgerValid: boolean | undefined = typeof vh?.ledger_valid === "boolean" ? vh.ledger_valid : undefined;
      const events = num(vh?.total_events, NaN);
      const vfDecisions = num(vfe?.total_decisions, NaN);
      const vfOpen = num(vfe?.escalated, 0);
      const sessions = Array.isArray(vsess) ? vsess.length : num(vsess?.total, NaN);

      const issues =
        (ledgerValid === false ? 1 : 0) + (denied > 0 ? 1 : 0) + (vfOpen > 0 ? 1 : 0);
      const integrityVal = ledgerValid === undefined ? "—" : ledgerValid ? "Verified" : "Attention";

      const model: OverviewModel = {
        posture: issues
          ? { title: "Attention needed", detail: `${issues} item${issues > 1 ? "s" : ""} need review`, tone: ledgerValid === false ? "crit" : "high" }
          : { title: "All clear", detail: "no open items", tone: "ok" },
        kpis: [
          { label: "Agents governed", value: Number.isNaN(agents) ? "—" : agents.toLocaleString(), meta: "Tessera" },
          { label: "Ledger integrity", value: integrityVal, meta: Number.isNaN(events) ? "Vestigia" : `${events.toLocaleString()} events`, tone: ledgerValid === false ? "var(--crit)" : "var(--ok)" },
          { label: "Detections · 24h", value: Number.isNaN(vfDecisions) ? "—" : String(vfDecisions), meta: `${vfOpen} open`, tone: vfOpen > 0 ? "var(--crit)" : undefined },
        ],
        pillars: [
          {
            key: "tessera", name: "Tessera", role: "Identity & delegation",
            stats: [
              { v: Number.isNaN(agents) ? "—" : String(agents), k: "agents" },
              { v: String(denied), k: "scope denials", tone: denied > 0 ? "var(--high)" : undefined },
            ],
            sev: denied > 0 ? "high" : "ok",
            sevLabel: denied > 0 ? `${denied} denied · 24h` : "No denials",
          },
          {
            key: "vestigia", name: "Vestigia", role: "Audit ledger",
            stats: [
              { v: integrityVal, k: "integrity", tone: ledgerValid === false ? "var(--crit)" : "var(--ok)" },
              { v: Number.isNaN(events) ? "—" : events.toLocaleString(), k: "events" },
            ],
            sev: ledgerValid === false ? "crit" : "ok",
            sevLabel: ledgerValid === false ? "Integrity check failed" : "All sealed",
          },
          {
            key: "verityflux", name: "VerityFlux", role: "Runtime detection",
            stats: [
              { v: Number.isNaN(sessions) ? "—" : String(sessions), k: "sessions" },
              { v: String(vfOpen), k: "open", tone: vfOpen > 0 ? "var(--crit)" : undefined },
            ],
            sev: vfOpen > 0 ? "crit" : "ok",
            sevLabel: vfOpen > 0 ? `${vfOpen} escalated` : "Nominal",
          },
        ],
      };
      return { source: "live", data: model };
    },
    retry: 0,
  });
}
