import { Routes, Route, Navigate } from "react-router-dom";
import AppShell from "./components/AppShell";
import Overview from "./pages/Overview";
import Tessera from "./pages/Tessera";
import Vestigia from "./pages/Vestigia";
import VerityFlux from "./pages/VerityFlux";

export default function App() {
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
