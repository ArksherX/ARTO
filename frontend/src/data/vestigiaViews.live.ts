import { useQuery } from "@tanstack/react-query";
import { vestigia } from "../lib/api";
import { sampleVestigia, type LedgerEvent } from "./vestigia";
import type { Sourced } from "./verityflux.live";

const t = (iso: unknown) => (typeof iso === "string" && iso.length >= 19 ? iso.slice(11, 19) : String(iso ?? ""));
const short = (h: unknown) => {
  const s = String(h ?? "");
  return s.length > 10 ? `${s.slice(0, 4)}…${s.slice(-4)}` : s;
};

export function useVestigiaEvents(limit = 25) {
  return useQuery<Sourced<LedgerEvent[]>>({
    queryKey: ["vestigia", "events", limit],
    queryFn: async () => {
      try {
        const r = await (vestigia as any).GET("/events");
        if (r.error) throw r.error;
        const raw: any[] = (r.data as any)?.events ?? (r.data as any)?.items ?? [];
        const rows: LedgerEvent[] = raw.slice(0, limit).map((e) => ({
          seq: String(e?.event_id ?? ""),
          time: t(e?.timestamp),
          source: String(e?.actor_id ?? "—").replace(/_server$/, ""),
          event: String(e?.action_type ?? ""),
          summary: String(e?.evidence?.summary ?? ""),
          hash: short(e?.integrity_hash),
          prev: short(e?.previous_hash),
          status: String(e?.status ?? ""),
        }));
        return rows.length ? { source: "live", data: rows } : { source: "sample", data: sampleVestigia.events };
      } catch {
        return { source: "sample", data: sampleVestigia.events };
      }
    },
    retry: 0,
  });
}

export interface Playbook { name: string; description: string; trigger: string; steps: string[] }
const samplePlaybooks: Playbook[] = [
  { name: "Credential exfiltration", description: "Response to suspected secret leakage", trigger: "detection.blocked (exfil)", steps: ["Quarantine agent", "Revoke tokens", "Notify on-call", "Open incident"] },
];

export function usePlaybooks() {
  return useQuery<Sourced<Playbook[]>>({
    queryKey: ["vestigia", "playbooks"],
    queryFn: async () => {
      try {
        const r = await (vestigia as any).GET("/playbooks");
        if (r.error) throw r.error;
        const raw: any[] = (r.data as any)?.playbooks ?? (Array.isArray(r.data) ? r.data : []);
        const rows: Playbook[] = raw.map((p) => ({
          name: String(p?.name ?? ""), description: String(p?.description ?? ""),
          trigger: String(p?.trigger ?? ""),
          steps: Array.isArray(p?.steps) ? p.steps.map(String) : [],
        }));
        return rows.length ? { source: "live", data: rows } : { source: "sample", data: samplePlaybooks };
      } catch {
        return { source: "sample", data: samplePlaybooks };
      }
    },
    retry: 0,
  });
}
