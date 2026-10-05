export interface LedgerEvent {
  seq: string; time: string; source: string; event: string;
  summary: string; hash: string; prev: string; status: string;
}
export interface IntegrityIssue { severity: string; type: string; description: string; entry?: number }
export interface VestigiaModel {
  integrity: { valid: boolean | undefined; totalEntries: number; issues: IntegrityIssue[] };
  totalEvents: number;
  events: LedgerEvent[];
}

export const sampleVestigia: VestigiaModel = {
  integrity: { valid: true, totalEntries: 10482, issues: [] },
  totalEvents: 8214,
  events: [
    { seq: "event_010482", time: "13:40:02", source: "vestigia", event: "SEGMENT_SEALED", summary: "segment #10482 sealed", hash: "a3f19c21", prev: "b8e43f05", status: "SUCCESS" },
    { seq: "event_010481", time: "13:33:18", source: "tessera", event: "APPROVAL_GRANTED", summary: "dual-control req-2214", hash: "55de81c0", prev: "0a3cee19", status: "SUCCESS" },
    { seq: "event_010480", time: "13:29:06", source: "verityflux", event: "DETECTION_FLAGGED", summary: "prompt-injection blocked", hash: "b2fa7701", prev: "cc4192b7", status: "WARNING" },
  ],
};
