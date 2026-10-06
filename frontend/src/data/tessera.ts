export interface AgentRow {
  id: string; role: string; scopes: string[]; status: string; bound: boolean; trust: number; by: string;
}
export interface TesseraModel {
  agents: number; delegations: number; denied: number; registry: AgentRow[];
}

export const sampleTessera: TesseraModel = {
  agents: 1284, delegations: 918, denied: 3,
  registry: [
    { id: "a-3391", role: "Orchestrator", scopes: ["memory:read", "tools:search", "deploy:request"], status: "active", bound: true, trust: 100, by: "svc-root" },
    { id: "a-7781", role: "Retriever", scopes: ["memory:read"], status: "active", bound: true, trust: 98, by: "a-3391" },
    { id: "a-9004", role: "Legacy bot", scopes: ["tools:search"], status: "active", bound: false, trust: 72, by: "svc-root" },
  ],
};

// Sections with no live endpoint yet — rendered as sample, tagged in the UI.
export interface ChainScope { s: string; g?: boolean; d?: boolean }
export interface ChainNode { role: string; name: string; id: string; scopes: ChainScope[] }
export const sampleChain: ChainNode[] = [
  { role: "Principal", name: "svc-root", id: "service account", scopes: [{ s: "memory:*" }, { s: "tools:*" }, { s: "deploy:*" }, { s: "pii:*" }] },
  { role: "Agent", name: "Orchestrator", id: "a-3391 · DPoP", scopes: [{ s: "memory:read", g: true }, { s: "tools:search", g: true }, { s: "deploy:request", g: true }, { s: "admin.*", d: true }] },
  { role: "Sub-agent", name: "Retriever", id: "a-7781 · DPoP", scopes: [{ s: "memory:read", g: true }] },
];

export const sampleApprovals = [
  { title: "PII export grant", req: "req-2219 · a-5120", sev: "crit" as const, a1: false, a2: false },
  { title: "Deploy approval", req: "req-2214 · a-3391", sev: "high" as const, a1: true, a2: false },
  { title: "Scope grant · tools:write", req: "req-2201 · a-6002", sev: "med" as const, a1: true, a2: false },
];

export const samplePosture = [
  { k: "DPoP sender-binding", v: "96%", w: 96 },
  { k: "Action signature", v: "92%", w: 92 },
  { k: "Memory binding", v: "88%", w: 88 },
];
