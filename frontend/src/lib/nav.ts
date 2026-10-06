export interface NavItem {
  to: string;
  label: string;
  end?: boolean; // exact match (pillar landing route)
}

// Top bar: pillars + global Approvals/Settings (merged, not per-pillar).
export const topNav: NavItem[] = [
  { to: "/overview", label: "Overview", end: true },
  { to: "/tessera", label: "Tessera" },
  { to: "/vestigia", label: "Vestigia" },
  { to: "/verityflux", label: "VerityFlux" },
  { to: "/approvals", label: "Approvals", end: true },
  { to: "/settings", label: "Settings", end: true },
];

export const tesseraNav: NavItem[] = [
  { to: "/tessera", label: "Dashboard", end: true },
  { to: "/tessera/agents", label: "Agent Registry" },
  { to: "/tessera/tokens", label: "Token Generator" },
  { to: "/tessera/gatekeeper", label: "Gatekeeper" },
  { to: "/tessera/revocation", label: "Revocation" },
  { to: "/tessera/bulk", label: "Bulk Uploads" },
];

export const vestigiaNav: NavItem[] = [
  { to: "/vestigia", label: "Dashboard", end: true },
  { to: "/vestigia/stats", label: "Statistics" },
  { to: "/vestigia/audit", label: "Audit Trail" },
  { to: "/vestigia/forensics", label: "Forensics" },
  { to: "/vestigia/siem", label: "SIEM Alerts" },
  { to: "/vestigia/killswitch", label: "Kill-Switch" },
  { to: "/vestigia/nl", label: "NL Query" },
  { to: "/vestigia/playbooks", label: "Playbooks" },
  { to: "/vestigia/risk", label: "Risk Forecast" },
  { to: "/vestigia/uploads", label: "Uploads" },
  { to: "/vestigia/tenants", label: "Tenants" },
];

export const verityfluxNav: NavItem[] = [
  { to: "/verityflux", label: "Firewall Activity", end: true },
  { to: "/verityflux/soc", label: "SOC Command" },
  { to: "/verityflux/scans", label: "Scanning & Assessment" },
  { to: "/verityflux/agents", label: "Agent Monitoring" },
  { to: "/verityflux/incidents", label: "Incidents" },
  { to: "/verityflux/vulns", label: "Vulnerabilities" },
  { to: "/verityflux/policy", label: "Enforcement Policy" },
  { to: "/verityflux/aibom", label: "AIBOM" },
];
