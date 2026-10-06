// Live data layer for the VerityFlux screen.
//
// Each hook calls a REAL VerityFlux endpoint through the typed client and maps
// the response to the UI model. The endpoints return loosely-typed bodies in
// the OpenAPI spec, so mapping is defensive and every hook FALLS BACK to the
// sample data when the backend is unreachable or a field is missing. The page
// shows a per-section Live/Sample badge based on `source`.
import { useQuery } from "@tanstack/react-query";
import { verityflux } from "../lib/api";
import {
  detections as sampleDetections,
  trajectory as sampleTrajectory,
  type Detection,
  type Intent,
  type Channel,
  type Action,
  type TrajectoryModel,
} from "./verityflux";

export type Source = "live" | "sample";
export interface Sourced<T> {
  source: Source;
  data: T;
}

const INTENTS: Intent[] = ["exploit", "hostile", "probing", "benign", "unknown"];
const CHANNELS: Channel[] = ["user", "tool", "memory", "data"];

/** Is the VerityFlux API reachable? Drives the global Live/Sample badge. */
export function useLiveStatus() {
  return useQuery({
    queryKey: ["vf", "health"],
    queryFn: async (): Promise<boolean> => {
      const { error } = await verityflux.GET("/health");
      if (error) throw new Error("unreachable");
      return true;
    },
    retry: 0,
    refetchInterval: 30_000,
  });
}

function num(v: unknown, d = 0): number {
  const n = typeof v === "string" ? parseFloat(v) : (v as number);
  return Number.isFinite(n) ? n : d;
}

export function useTrajectory() {
  return useQuery<Sourced<TrajectoryModel>>({
    queryKey: ["vf", "trajectory"],
    queryFn: async () => {
      try {
        const s = await verityflux.GET("/api/v2/sessions");
        if (s.error) throw s.error;
        const raw = s.data as any;
        const sessions: any[] = Array.isArray(raw) ? raw : raw?.items ?? raw?.sessions ?? [];
        const sid = sessions[0]?.session_id ?? sessions[0]?.id;
        if (!sid) return { source: "sample", data: sampleTrajectory };

        const st = await verityflux.GET("/api/v2/session/{session_id}/state", {
          params: { path: { session_id: String(sid) } },
        });
        if (st.error) throw st.error;
        const d = st.data as any;
        const history: unknown[] = d?.drift_history ?? d?.state?.drift_history ?? [];
        if (!Array.isArray(history) || history.length === 0) {
          return { source: "sample", data: sampleTrajectory };
        }
        const points = history.map((v, i) => ({ turn: i + 1, drift: num(v) }));
        const flagged: unknown[] = Array.isArray(d?.flagged_turns) ? d.flagged_turns : [];
        const turningPoint = flagged.length ? num(flagged[0], points.length) : points.length;
        return {
          source: "live",
          data: {
            session: String(sid),
            agent: String(d?.agent_id ?? sessions[0]?.agent_id ?? "—"),
            turningPoint,
            elevated: num(d?.elevated_threshold, 0.33),
            critical: num(d?.critical_threshold, 0.55),
            points,
          },
        };
      } catch {
        return { source: "sample", data: sampleTrajectory };
      }
    },
    retry: 0,
  });
}

function coerceIntent(v: unknown): Intent {
  const s = String(v ?? "").toLowerCase();
  return (INTENTS.find((i) => s.includes(i)) ?? "unknown") as Intent;
}
function coerceChannel(v: unknown): Channel {
  const s = String(v ?? "").toLowerCase();
  return (CHANNELS.find((c) => s.includes(c)) ?? "user") as Channel;
}
function coerceAction(v: unknown): Action {
  const s = String(v ?? "").toLowerCase();
  if (s.includes("block")) return "Blocked";
  if (s.includes("review")) return "Requires review";
  if (s.includes("allow")) return "Allowed";
  return "Flagged";
}

export function useDetections() {
  return useQuery<Sourced<Detection[]>>({
    queryKey: ["vf", "events"],
    queryFn: async () => {
      try {
        const r = await verityflux.GET("/api/v1/soc/events");
        if (r.error) throw r.error;
        const raw = r.data as any;
        const items: any[] = raw?.items ?? (Array.isArray(raw) ? raw : []);
        const mapped: Detection[] = items
          .map((e): Detection | null => {
            const time = e?.timestamp ?? e?.time ?? e?.created_at;
            const input = e?.input ?? e?.message ?? e?.description ?? e?.detail;
            if (!time && !input) return null;
            const scoreRaw = e?.hostility_score ?? e?.score;
            return {
              time: String(time ?? "").slice(11, 19) || String(time ?? ""),
              session: String(e?.session_id ?? e?.session ?? "—"),
              channel: coerceChannel(e?.channel ?? e?.source),
              input: String(input ?? ""),
              intent: coerceIntent(e?.intent ?? e?.intent_class),
              score: scoreRaw == null ? null : num(scoreRaw),
              action: coerceAction(e?.action ?? e?.verdict ?? e?.status),
            };
          })
          .filter((x): x is Detection => x !== null);
        if (mapped.length === 0) return { source: "sample", data: sampleDetections };
        return { source: "live", data: mapped };
      } catch {
        return { source: "sample", data: sampleDetections };
      }
    },
    retry: 0,
  });
}
