import { useQuery } from "@tanstack/react-query";
import { vestigia } from "../lib/api";
import { sampleVestigia, type VestigiaModel, type LedgerEvent } from "./vestigia";
import type { Sourced } from "./verityflux.live";

function num(v: unknown, d = 0): number {
  const n = typeof v === "string" ? parseFloat(v) : (v as number);
  return Number.isFinite(n) ? n : d;
}
const t = (iso: unknown): string => (typeof iso === "string" && iso.length >= 19 ? iso.slice(11, 19) : String(iso ?? ""));
const short = (h: unknown): string => {
  const s = String(h ?? "");
  return s.length > 10 ? `${s.slice(0, 4)}…${s.slice(-4)}` : s;
};
async function get(path: string): Promise<any> {
  const r = await (vestigia as any).GET(path);
  if (r.error) throw r.error;
  return r.data;
}

export function useVestigia() {
  return useQuery<Sourced<VestigiaModel>>({
    queryKey: ["vestigia"],
    queryFn: async () => {
      try {
        const [integ, evq, stats, health] = await Promise.allSettled([
          get("/integrity"), get("/events"), get("/statistics"), get("/health"),
        ]);
        const iv = integ.status === "fulfilled" ? (integ.value as any) : null;
        const ev = evq.status === "fulfilled" ? (evq.value as any) : null;
        const st = stats.status === "fulfilled" ? (stats.value as any) : null;
        const he = health.status === "fulfilled" ? (health.value as any) : null;
        if (!iv && !ev && !st && !he) return { source: "sample", data: sampleVestigia };

        const rawEvents: any[] = ev?.events ?? ev?.items ?? (Array.isArray(ev) ? ev : []);
        const events: LedgerEvent[] = rawEvents.slice(0, 8).map((e) => ({
          seq: String(e?.event_id ?? e?.seq ?? ""),
          time: t(e?.timestamp ?? e?.time),
          source: String(e?.actor_id ?? e?.source ?? "—").replace(/_server$/, ""),
          event: String(e?.action_type ?? e?.event ?? ""),
          summary: String(e?.evidence?.summary ?? e?.summary ?? ""),
          hash: short(e?.integrity_hash ?? e?.hash),
          prev: short(e?.previous_hash ?? e?.prev),
          status: String(e?.status ?? ""),
        }));

        const valid: boolean | undefined =
          typeof iv?.is_valid === "boolean" ? iv.is_valid :
          typeof he?.ledger_valid === "boolean" ? he.ledger_valid : undefined;
        const issues = Array.isArray(iv?.issues)
          ? iv.issues.slice(0, 5).map((x: any) => ({
              severity: String(x?.severity ?? ""), type: String(x?.type ?? ""),
              description: String(x?.description ?? ""), entry: num(x?.entry_index, NaN),
            }))
          : [];

        return {
          source: "live",
          data: {
            integrity: {
              valid,
              totalEntries: num(iv?.total_entries ?? st?.total_events ?? he?.total_events, NaN),
              issues,
            },
            totalEvents: num(st?.total_events ?? he?.total_events, NaN),
            events: events.length ? events : sampleVestigia.events,
          },
        };
      } catch {
        return { source: "sample", data: sampleVestigia };
      }
    },
    retry: 0,
  });
}
