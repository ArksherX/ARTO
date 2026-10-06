import { useQuery } from "@tanstack/react-query";
import { vestigia } from "../lib/api";
import type { Sourced } from "./verityflux.live";

export interface StatBucket { k: string; n: number }
export interface StatsModel {
  totalEvents: number;
  firstEntry: string;
  lastEntry: string;
  status: StatBucket[];
  actions: StatBucket[];
}

const sampleStats: StatsModel = {
  totalEvents: 8214,
  firstEntry: "2026-06-29T09:49:13Z",
  lastEntry: "2026-10-06T08:14:13Z",
  status: [{ k: "SUCCESS", n: 7993 }, { k: "WARNING", n: 221 }],
  actions: [
    { k: "API_REQUEST", n: 7600 }, { k: "TOOL_EXECUTION", n: 420 },
    { k: "TOKEN_ISSUED", n: 118 }, { k: "IDENTITY_VERIFIED", n: 51 },
  ],
};

function buckets(obj: unknown): StatBucket[] {
  if (!obj || typeof obj !== "object") return [];
  return Object.entries(obj as Record<string, unknown>)
    .map(([k, v]) => ({ k, n: Number(v) || 0 }))
    .sort((a, b) => b.n - a.n);
}

export function useVestigiaStats() {
  return useQuery<Sourced<StatsModel>>({
    queryKey: ["vestigia", "stats"],
    queryFn: async () => {
      try {
        const r = await (vestigia as any).GET("/statistics");
        if (r.error) throw r.error;
        const d = r.data as any;
        return {
          source: "live",
          data: {
            totalEvents: Number(d?.total_events) || 0,
            firstEntry: String(d?.first_entry ?? ""),
            lastEntry: String(d?.last_entry ?? ""),
            status: buckets(d?.status_breakdown),
            actions: buckets(d?.action_breakdown),
          },
        };
      } catch {
        return { source: "sample", data: sampleStats };
      }
    },
    retry: 0,
  });
}
