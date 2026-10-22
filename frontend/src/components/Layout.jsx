import { NavLink, Outlet } from "react-router-dom";
import { useState } from "react";
import { api } from "../services/api";
import { useApi } from "../services/useApi";
import { useAuth } from "../services/auth";

const NAV = [
  ["/", "Overview", ["red_team", "blue_team", "admin"]],
  ["/red-team", "Red Team Console", ["red_team"]],
  ["/blue-team", "Blue Team Console", ["blue_team", "admin"]],
  ["/history", "Test History", ["red_team", "blue_team", "admin"]],
  ["/audit", "Audit Logs", ["admin"]],
  ["/settings", "Settings", ["red_team", "blue_team", "admin"]],
];

export default function Layout() {
  const [open, setOpen] = useState(false);
  const { user, logout } = useAuth();
  const { data, error, loading } = useApi(api.health);
  const state = loading ? "checking" : error ? "offline" : "online";
  return (
    <div className="shell">
      <button className="menu-btn" onClick={() => setOpen(!open)} aria-label="Toggle navigation">Menu</button>
      <aside className={`sidebar ${open ? "open" : ""}`}>
        <div className="brand">
          <div className="brand-name">LeakProof AI</div>
          <div className="brand-tag">Secure AI Safety Testing &amp; Evaluation Platform</div>
        </div>
        <nav>
          {NAV.filter(([, , roles]) => roles.includes(user.role)).map(([to, label]) => (
            <NavLink key={to} to={to} end={to === "/"} onClick={() => setOpen(false)}>{label}</NavLink>
          ))}
        </nav>
        <div className="side-status user-box">
          <div>{user.email}</div>
          <div className="role-tag">{user.role.replace("_", " ")}</div>
          <button className="btn" onClick={logout}>Sign out</button>
        </div>
        <div className="side-status">
          <span className={`dot ${state}`} />
          Backend {state}{data ? ` · v${data.version}` : ""}
        </div>
      </aside>
      <main className="content"><Outlet /></main>
    </div>
  );
}
