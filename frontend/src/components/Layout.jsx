import { NavLink, Outlet } from "react-router-dom";
import { useState } from "react";
import { LayoutDashboard, Crosshair, ShieldCheck, History, ScrollText, Settings, ShieldHalf, LogOut, Menu } from "lucide-react";
import { api } from "../services/api";
import { useApi } from "../services/useApi";
import { useAuth } from "../services/auth";

const NAV = [
  ["/", "Dashboard", LayoutDashboard, ["red_team", "blue_team", "admin"]],
  ["/red-team", "Red Team Console", Crosshair, ["red_team"]],
  ["/blue-team", "Blue Team Console", ShieldCheck, ["blue_team", "admin"]],
  ["/history", "Test History", History, ["red_team", "blue_team", "admin"]],
  ["/audit", "Audit Logs", ScrollText, ["admin"]],
  ["/settings", "Settings", Settings, ["red_team", "blue_team", "admin"]],
];

export default function Layout() {
  const [open, setOpen] = useState(false);
  const { user, logout } = useAuth();
  const health = useApi(api.health);
  const ai = useApi(api.aiHealth);
  const be = health.loading ? "checking" : health.error ? "offline" : "online";
  const aiState = ai.loading ? "checking" : ai.data?.ok ? "online" : "offline";
  const name = user.email.split("@")[0];
  return (
    <div className="shell">
      <aside className={`sidebar ${open ? "open" : ""}`}>
        <div className="brand">
          <ShieldHalf size={34} strokeWidth={1.6} />
          <div>
            <div className="brand-name">LeakProof AI</div>
            <div className="brand-tag">AI SECURITY PLATFORM</div>
          </div>
        </div>
        <nav aria-label="Main">
          {NAV.filter(([, , , roles]) => roles.includes(user.role)).map(([to, label, Icon]) => (
            <NavLink key={to} to={to} end={to === "/"} onClick={() => setOpen(false)}>
              <Icon size={18} strokeWidth={1.8} /> {label}
            </NavLink>
          ))}
        </nav>
        <div className="side-status">
          <div className="muted small">Signed in</div>
          <div className="side-email">{user.email}</div>
          <div className="role-tag">{user.role.replace("_", " ")}</div>
        </div>
      </aside>
      <div className="main-col">
        <header className="topbar">
          <button className="menu-btn" onClick={() => setOpen(!open)} aria-label="Toggle navigation"><Menu size={20} /></button>
          <div className="pills">
            <span className="pill"><span className={`dot ${be}`} />Backend {be}{health.data ? ` · v${health.data.version}` : ""}</span>
            <span className="pill"><span className={`dot ${aiState}`} />AI model {aiState === "online" ? "connected" : aiState === "checking" ? "checking" : "unavailable"}{ai.data?.model ? ` · ${ai.data.model}` : ""}</span>
          </div>
          <div className="user-chip">
            <span className="avatar" aria-hidden="true">{name.slice(0, 2).toUpperCase()}</span>
            <div className="user-meta"><div>{name}</div><div className="muted small">{user.role.replace("_", " ")}</div></div>
            <button className="icon-btn" onClick={logout} aria-label="Sign out" title="Sign out"><LogOut size={18} /></button>
          </div>
        </header>
        <main className="content"><Outlet /></main>
      </div>
    </div>
  );
}
