import { Routes, Route, Navigate, useLocation } from "react-router-dom";
import AppShell from "./components/AppShell";
import PillarLayout from "./components/PillarLayout";
import Placeholder from "./components/Placeholder";
import Overview from "./pages/Overview";
import Tessera from "./pages/Tessera";
import Vestigia from "./pages/Vestigia";
import VestigiaStatistics from "./pages/VestigiaStatistics";
import VestigiaAudit from "./pages/VestigiaAudit";
import VestigiaPlaybooks from "./pages/VestigiaPlaybooks";
import VerityFluxSOC from "./pages/VerityFluxSOC";
import TesseraRegistry from "./pages/TesseraRegistry";
import VerityFlux from "./pages/VerityFlux";
import Approvals from "./pages/Approvals";
import Settings from "./pages/Settings";
import Login from "./pages/Login";
import { tesseraNav, vestigiaNav, verityfluxNav } from "./lib/nav";
import { requireLogin, isAuthed } from "./lib/auth";

export default function App() {
  const loc = useLocation();
  if (loc.pathname === "/login") return <Login />;
  if (requireLogin && !isAuthed()) return <Navigate to="/login" replace />;

  return (
    <AppShell>
      <Routes>
        <Route path="/" element={<Navigate to="/overview" replace />} />
        <Route path="/overview" element={<Overview />} />

        {/* Tessera */}
        <Route path="/tessera" element={<PillarLayout nav={tesseraNav} />}>
          <Route index element={<Tessera />} />
          <Route path="agents" element={<TesseraRegistry />} />
          <Route path="tokens" element={<Placeholder title="Token Generator" endpoint="POST /tokens/request · /tokens/delegate" note="Action tool — needs real auth (FE-1)." />} />
          <Route path="gatekeeper" element={<Placeholder title="Gatekeeper" endpoint="POST /access/validate · /tokens/validate" note="Action tool — needs real auth (FE-1)." />} />
          <Route path="revocation" element={<Placeholder title="Revocation Manager" endpoint="POST /tokens/revoke · /agents/{id}/keys/revoke" note="Action tool — needs real auth (FE-1)." />} />
          <Route path="bulk" element={<Placeholder title="Bulk Uploads" endpoint="POST /agents/register (batch)" note="Action tool, low priority." />} />
        </Route>

        {/* Vestigia */}
        <Route path="/vestigia" element={<PillarLayout nav={vestigiaNav} />}>
          <Route index element={<Vestigia />} />
          <Route path="stats" element={<VestigiaStatistics />} />
          <Route path="audit" element={<VestigiaAudit />} />
          <Route path="forensics" element={<Placeholder title="Forensics" endpoint="/events/{id} · POST /anomalies/score" />} />
          <Route path="siem" element={<Placeholder title="SIEM Alerts" endpoint="/threat-cards · POST /webhooks/siem" />} />
          <Route path="killswitch" element={<Placeholder title="Kill-Switch" endpoint="lockdown control" note="Highest-risk action — build last, behind a hard confirm." />} />
          <Route path="nl" element={<Placeholder title="NL Query" endpoint="POST /nl/query" note="Action tool." />} />
          <Route path="playbooks" element={<VestigiaPlaybooks />} />
          <Route path="risk" element={<Placeholder title="Risk Forecast" endpoint="/risk/forecast" />} />
          <Route path="uploads" element={<Placeholder title="Uploads" endpoint="POST /events/batch" note="Action tool, low priority." />} />
          <Route path="tenants" element={<Placeholder title="Tenants" endpoint="POST /tenants · /tenants/{id}/apikeys · /users" note="Admin action tool." />} />
        </Route>

        {/* VerityFlux */}
        <Route path="/verityflux" element={<PillarLayout nav={verityfluxNav} />}>
          <Route index element={<VerityFlux />} />
          <Route path="soc" element={<VerityFluxSOC />} />
          <Route path="scans" element={<Placeholder title="Scanning & Assessment" endpoint="POST+GET /api/v1/scans · /scans/{id}/findings · /skills/assess" note="Action tool." />} />
          <Route path="agents" element={<Placeholder title="Agent Monitoring" endpoint="/api/v1/soc/agents · POST heartbeat/quarantine" />} />
          <Route path="incidents" element={<Placeholder title="Incident Management" endpoint="/api/v1/soc/incidents · acknowledge/assign/resolve" />} />
          <Route path="vulns" element={<Placeholder title="Vulnerabilities" endpoint="/api/v1/vulnerabilities · /owasp/llm · /owasp/agentic" />} />
          <Route path="policy" element={<Placeholder title="Enforcement Policy" endpoint="GET/POST /api/v1/policy · /policy/reload" note="Action tool." />} />
          <Route path="aibom" element={<Placeholder title="AIBOM" endpoint="/api/v2/aibom · register · verify" />} />
        </Route>

        <Route path="/approvals" element={<Approvals />} />
        <Route path="/settings" element={<Settings />} />
        <Route path="*" element={<Navigate to="/overview" replace />} />
      </Routes>
    </AppShell>
  );
}
