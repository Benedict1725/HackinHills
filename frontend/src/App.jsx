import { Navigate, Route, Routes } from "react-router-dom";
import Layout from "./components/Layout";
import Overview from "./pages/Overview";
import RedTeam from "./pages/RedTeam";
import BlueTeam from "./pages/BlueTeam";
import History from "./pages/History";
import TestDetail from "./pages/TestDetail";
import Audit from "./pages/Audit";
import Settings from "./pages/Settings";
import Login from "./pages/Login";
import { useAuth } from "./services/auth";

// Client-side role gates are a convenience only. The backend enforces every permission.
function Gate({ roles, children }) {
  const { user } = useAuth();
  return roles.includes(user.role) ? children : <div className="state">Your role ({user.role.replace("_", " ")}) does not have access to this page.</div>;
}

export default function App() {
  const { user, ready } = useAuth();
  if (!ready) return <div className="state">Loading…</div>;
  if (!user) return <Login />;
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route index element={<Overview />} />
        <Route path="red-team" element={<Gate roles={["red_team"]}><RedTeam /></Gate>} />
        <Route path="blue-team" element={<Gate roles={["blue_team", "admin"]}><BlueTeam /></Gate>} />
        <Route path="history" element={<History />} />
        <Route path="history/:id" element={<TestDetail />} />
        <Route path="audit" element={<Gate roles={["admin"]}><Audit /></Gate>} />
        <Route path="settings" element={<Settings />} />
        <Route path="login" element={<Navigate to="/" replace />} />
        <Route path="*" element={<div className="state">Page not found.</div>} />
      </Route>
    </Routes>
  );
}
