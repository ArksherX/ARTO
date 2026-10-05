import { useQuery } from "@tanstack/react-query";
import { tessera } from "../lib/api";
import { sampleTessera, type TesseraModel, type AgentRow } from "./tessera";
import type { Sourced } from "./verityflux.live";

function num(v: unknown, d = 0): number {
  const n = typeof v === "string" ? parseFloat(v) : (v as number);
  return Number.isFinite(n) ? n : d;
}
async function get(path: string): Promise<any> {
  const r = await (tessera as any).GET(path);
  if (r.error) throw r.error;
  return r.data;
}

export function useTessera() {
  return useQuery<Sourced<TesseraModel>>({
    queryKey: ["tessera"],
    queryFn: async () => {
      try {
        const [agentsR, delegR, effR] = await Promise.allSettled([
          get("/agents/list"), get("/tokens/delegations"), get("/security/efficacy"),
        ]);
        const ag = agentsR.status === "fulfilled" ? (agentsR.value as any) : null;
        const dl = delegR.status === "fulfilled" ? (delegR.value as any) : null;
        const ef = effR.status === "fulfilled" ? (effR.value as any) : null;
        if (!ag && !dl && !ef) return { source: "sample", data: sampleTessera };

        const list: any[] = ag?.agents ?? (Array.isArray(ag) ? ag : []);
        const registry: AgentRow[] = list.slice(0, 12).map((a) => ({
          id: String(a?.agent_id ?? "—"),
          role: String(a?.owner ?? a?.role ?? "agent"),
          scopes: Array.isArray(a?.allowed_tools) ? a.allowed_tools.map(String) : [],
          status: String(a?.status ?? "—"),
          bound: Boolean(a?.active_key_id),
          trust: num(a?.trust_score, NaN),
          by: String((Array.isArray(a?.allowed_delegates) && a.allowed_delegates[0]) || a?.owner || "—"),
        }));

        return {
          source: "live",
          data: {
            agents: registry.length ? list.length : num(ag?.total, NaN),
            delegations: num(dl?.total, NaN),
            denied: num(ef?.denied_total, 0),
            registry: registry.length ? registry : sampleTessera.registry,
          },
        };
      } catch {
        return { source: "sample", data: sampleTessera };
      }
    },
    retry: 0,
  });
}
