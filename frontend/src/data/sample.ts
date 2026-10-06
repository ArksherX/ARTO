// Placeholder data so screens render before the live API hooks are wired.
// Each page will replace these with TanStack Query calls to the typed clients
// in src/lib/api.ts. Clearly sample — never presented as real figures.

export const overviewKpis = [
  { label: "Agents governed", value: "1,284", meta: "across 3 orgs · 342 live tokens" },
  { label: "Ledger integrity", value: "Verified", meta: "chain depth 10,482", tone: "var(--ok)" },
  { label: "Detections · 24h", value: "37", meta: "1 critical · 3 open", tone: "var(--crit)" },
];

export const pillars = [
  {
    key: "tessera",
    name: "Tessera",
    role: "Identity & delegation",
    stats: [
      { v: "1,284", k: "agents" },
      { v: "342", k: "tokens" },
      { v: "1", k: "scope breach", tone: "var(--high)" },
    ],
    sev: "high" as const,
    sevLabel: "1 high · 24h",
  },
  {
    key: "vestigia",
    name: "Vestigia",
    role: "Audit ledger",
    stats: [
      { v: "Verified", k: "integrity", tone: "var(--ok)" },
      { v: "10,482", k: "depth" },
    ],
    sev: "ok" as const,
    sevLabel: "All sealed",
  },
  {
    key: "verityflux",
    name: "VerityFlux",
    role: "Runtime detection",
    stats: [
      { v: "37", k: "detections" },
      { v: "3", k: "open", tone: "var(--crit)" },
    ],
    sev: "crit" as const,
    sevLabel: "1 critical · active",
  },
];
