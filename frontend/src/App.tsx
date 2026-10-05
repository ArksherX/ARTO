import { Routes, Route, Navigate, useLocation } from "react-router-dom";
import AppShell from "./components/AppShell";
import Overview from "./pages/Overview";
import Tessera from "./pages/Tessera";
import Vestigia from "./pages/Vestigia";
import VerityFlux from "./pages/VerityFlux";
import Login from "./pages/Login";
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
        <Route path="/tessera" element={<Tessera />} />
        <Route path="/vestigia" element={<Vestigia />} />
        <Route path="/verityflux" element={<VerityFlux />} />
        <Route path="*" element={<Navigate to="/overview" replace />} />
      </Routes>
    </AppShell>
  );
}
