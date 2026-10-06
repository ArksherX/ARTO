import { useQuery } from "@tanstack/react-query";
import { verityflux } from "../lib/api";
import type { Sourced } from "./verityflux.live";

export interface SocModel {
  threat: string;
  incidentsOpen: number;
  incidentsTotal: number;
  slaCompliance: number;
  slaBreaches: number;
  eventsTotal: number;
  blocked: number;
  allowed: number;
  alertsTotal: number;
  alertsNew: number;
  agentsTotal: number;
  agentsHealthy: number;
}

const sample: SocModel = {
  threat: "low", incidentsOpen: 0, incidentsTotal: 0, slaCompliance: 100, slaBreaches: 0,
  eventsTotal: 2940, blocked: 24, allowed: 2894, alertsTotal: 0, alertsNew: 0,
  agentsTotal: 4, agentsHealthy: 3,
};
const n = (v: unknown, d = 0) => (Number.isFinite(Number(v)) ? Number(v) : d);

export function useSoc() {
  return useQuery<Sourced<SocModel>>({
    queryKey: ["vf", "soc"],
    queryFn: async () => {
      try {
        const r = await (verityflux as any).GET("/api/v1/soc/metrics");
        if (r.error) throw r.error;
        const d = r.data as any;
        return {
          source: "live",
          data: {
            threat: String(d?.threat_level ?? "unknown"),
            incidentsOpen: n(d?.incidents?.open), incidentsTotal: n(d?.incidents?.total),
            slaCompliance: n(d?.sla?.compliance_rate), slaBreaches: n(d?.sla?.breaches),
            eventsTotal: n(d?.events?.total), blocked: n(d?.events?.blocked), allowed: n(d?.events?.allowed),
            alertsTotal: n(d?.alerts?.total), alertsNew: n(d?.alerts?.new),
            agentsTotal: n(d?.agents?.total), agentsHealthy: n(d?.agents?.healthy),
          },
        };
      } catch {
        return { source: "sample", data: sample };
      }
    },
    retry: 0,
  });
}
