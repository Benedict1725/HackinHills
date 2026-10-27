import { useCallback, useEffect, useRef, useState } from "react";
import { UserPlus } from "lucide-react";
import { api } from "../services/api";
import { useApi } from "../services/useApi";
import { useAuth } from "../services/auth";
import { ErrorState, ExecBadge, Loading, PageHeader, SeverityBadge, VerdictBadge, fmt } from "../components/ui";
import Audit from "./Audit";
import Settings from "./Settings";

const ROLE_LABEL = { red_team: "Red Team", blue_team: "Blue Team", admin: "Admin" };
const TABS = [["overview", "Overview"], ["users", "User Management"], ["roles", "Roles & Permissions"], ["activity", "Security Activity"], ["system", "System Status"]];

function Confirm({ title, children, confirmLabel, danger, onConfirm, onCancel, busy }) {
  const ref = useRef(null);
  useEffect(() => { ref.current?.focus(); const k = (e) => e.key === "Escape" && onCancel(); window.addEventListener("keydown", k); return () => window.removeEventListener("keydown", k); }, [onCancel]);
  return (
    <div className="modal-back" style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,.6)", display: "grid", placeItems: "center", zIndex: 50, padding: "1rem" }}>
      <div role="alertdialog" aria-modal="true" aria-labelledby="cf-t" className="card" style={{ maxWidth: 460 }}>
        <h2 id="cf-t">{title}</h2>{children}
        <div className="row" style={{ marginTop: "1rem" }}>
          <button className="btn" ref={ref} onClick={onCancel} disabled={busy}>Cancel</button>
          <button className={`btn ${danger ? "danger" : "accent"}`} onClick={onConfirm} disabled={busy}>{busy ? "Working…" : confirmLabel}</button>
        </div>
      </div>
    </div>);
}

function Overview() {
  const { data: d, error, loading, retry } = useApi(api.adminOverview);
  if (loading && !d) return <Loading label="Loading overview…" />;
  if (error) return <ErrorState message={error} onRetry={retry} />;
  return (
    <>
      {d.alerts.length === 0 ? <p className="alert-line" role="status"><span className="dot online" /> No operational problems detected.</p>
        : d.alerts.map((a, i) => <p key={i} className={`alert-line ${a.level}`} role="alert">{a.text}</p>)}
      <section className="stats">
        {[["Active accounts", `${d.users.active} of ${d.users.total}`], ["Tests in last 7 days", d.tests_last_7_days], ["Failed to run (7 days)", d.execution_errors_last_7_days], ["Access denied (7 days)", d.denied_last_7_days]].map(([l, v]) => (
          <div className="card stat" key={l}><div className="stat-value">{v}</div><div className="muted">{l}</div></div>))}
      </section>
      <section className="card"><h2>System health</h2>
        <p><span className={`dot ${d.database === "ok" ? "online" : "offline"}`} /> Database: {d.database === "ok" ? "working" : "problem"}</p>
        <p><span className={`dot ${d.ai.ok ? "online" : "offline"}`} /> AI model: {d.ai.ok ? `connected${d.ai.model ? ` (${d.ai.provider}/${d.ai.model})` : ""}` : `not reachable. ${d.ai.detail}`}</p>
        <p className="muted small">Active accounts by role: {Object.entries(d.users.by_role).map(([r, n]) => `${ROLE_LABEL[r]} ${n}`).join(" · ")}</p></section>
      <section className="card table-wrap"><h2>Recent test activity</h2>
        {d.recent_tests.length === 0 ? <div className="empty">No tests have been run yet.</div> : (
          <table><thead><tr><th>Test</th><th>Category</th><th>Run</th><th>Verdict</th><th>Severity</th><th>When</th></tr></thead>
            <tbody>{d.recent_tests.map((t) => <tr key={t.test_id}><td><code>{t.test_id}</code></td><td>{t.category.replace(/_/g, " ")}</td><td><ExecBadge status={t.execution_status} /></td><td><VerdictBadge verdict={t.security_verdict} executionStatus={t.execution_status} /></td><td><SeverityBadge severity={t.severity} /></td><td>{fmt(t.created_at)}</td></tr>)}</tbody></table>)}
      </section>
    </>);
}

function Users() {
  const { user: me } = useAuth();
  const [q, setQ] = useState(""), [role, setRole] = useState(""), [status, setStatus] = useState("");
  const fetcher = useCallback(() => api.adminUsers({ q, role, status }), [q, role, status]);
  const { data, error, loading, retry } = useApi(fetcher);
  const [pending, setPending] = useState(null), [busy, setBusy] = useState(false), [msg, setMsg] = useState(""), [err, setErr] = useState("");
  const [form, setForm] = useState(null);
  async function commit() {
    setBusy(true); setErr(""); setMsg("");
    try { await api.adminUpdateUser(pending.u.id, pending.patch); setMsg(`${pending.u.email}: ${pending.what}. Their sessions were signed out.`); setPending(null); retry(); }
    catch (e) { setErr(e.message); setPending(null); } finally { setBusy(false); }
  }
  async function create(e) {
    e.preventDefault(); setBusy(true); setErr(""); setMsg("");
    try { const u = await api.adminCreateUser(form); setMsg(`Account created for ${u.email}. Share the temporary password with them privately.`); setForm(null); retry(); }
    catch (x) { setErr(x.message); } finally { setBusy(false); }
  }
  return (
    <>
      <div className="row" style={{ marginBottom: "1rem", flexWrap: "wrap" }}>
        <input aria-label="Search users by email" placeholder="Search by email…" value={q} onChange={(e) => setQ(e.target.value)} style={{ maxWidth: 260 }} />
        <select aria-label="Filter by role" value={role} onChange={(e) => setRole(e.target.value)} style={{ width: "auto" }}><option value="">All roles</option>{Object.entries(ROLE_LABEL).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</select>
        <select aria-label="Filter by status" value={status} onChange={(e) => setStatus(e.target.value)} style={{ width: "auto" }}><option value="">Active and inactive</option><option value="active">Active</option><option value="inactive">Deactivated</option></select>
        <button className="btn accent" onClick={() => setForm({ email: "", role: "red_team", password: "" })}><UserPlus size={15} /> Add user</button>
      </div>
      {msg && <p role="status" style={{ color: "var(--teal)" }}>{msg}</p>}
      {err && <div className="state error" role="alert"><p>{err}</p></div>}
      {form && (
        <form className="card form" onSubmit={create} aria-label="Add user">
          <h2>Add user</h2>
          <label htmlFor="nu-email">Email</label><input id="nu-email" type="email" required value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} />
          <label htmlFor="nu-role">Role</label><select id="nu-role" value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value })}>{Object.entries(ROLE_LABEL).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</select>
          <label htmlFor="nu-pw">Temporary password <span className="muted small">(at least 12 characters)</span></label><input id="nu-pw" type="password" required minLength={12} autoComplete="new-password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} />
          <div className="row"><button className="btn accent" disabled={busy}>{busy ? "Creating…" : "Create account"}</button><button type="button" className="btn" onClick={() => setForm(null)}>Cancel</button></div>
        </form>)}
      {error ? <ErrorState message={error} onRetry={retry} /> : loading && !data ? <Loading label="Loading users…" /> : (
        <section className="card table-wrap">
          {data.items.length === 0 ? <div className="empty">No users match these filters.</div> : (
            <table><thead><tr><th>Email</th><th>Role</th><th>Status</th><th>Signed in now</th><th>Created</th><th>Actions</th></tr></thead>
              <tbody>{data.items.map((u) => {
                const self = u.email === me.email;
                return (<tr key={u.id}><td>{u.email}{self && <span className="muted small"> (you)</span>}</td>
                  <td><select aria-label={`Role for ${u.email}`} value={u.role} disabled={self} title={self ? "You cannot change your own role" : ""} style={{ width: "auto" }}
                    onChange={(e) => setPending({ u, patch: { role: e.target.value }, what: `role changed to ${ROLE_LABEL[e.target.value]}`, title: "Change role?", body: `${u.email} will become ${ROLE_LABEL[e.target.value]} and be signed out. Their access changes immediately.`, label: "Change role" })}>
                    {Object.entries(ROLE_LABEL).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</select></td>
                  <td><span className={`badge ${u.is_active ? "passed" : "na"}`}>{u.is_active ? "Active" : "Deactivated"}</span></td>
                  <td>{u.active_sessions}</td><td>{fmt(u.created_at)}</td>
                  <td>{u.is_active
                    ? <button className="btn" disabled={self} title={self ? "You cannot deactivate yourself" : ""} onClick={() => setPending({ u, patch: { is_active: false }, what: "deactivated", title: "Deactivate account?", body: `${u.email} will be signed out and cannot sign in until reactivated. Their test history is kept.`, label: "Deactivate", danger: true })}>Deactivate</button>
                    : <button className="btn" onClick={() => setPending({ u, patch: { is_active: true }, what: "reactivated", title: "Reactivate account?", body: `${u.email} will be able to sign in again.`, label: "Reactivate" })}>Reactivate</button>}</td></tr>);
              })}</tbody></table>)}
        </section>)}
      {pending && <Confirm title={pending.title} confirmLabel={pending.label} danger={pending.danger} busy={busy} onConfirm={commit} onCancel={() => setPending(null)}><p>{pending.body}</p></Confirm>}
      <p className="muted small">The server blocks you from deactivating or demoting yourself, and from removing the last active administrator. Passwords are never shown; users are not deleted so their history stays intact.</p>
    </>);
}

function Roles() {
  const rows = [["Red Team", "Runs attack tests against the AI and sees the results of its own tests.", "Cannot change protection, see Blue Team settings, manage users or read the audit log."],
    ["Blue Team", "Chooses and applies protection, runs the security test, reviews Red Team findings and retests them.", "Cannot manage users or read the audit log."],
    ["Admin", "Manages accounts, reads the audit log and system status, and can view protection settings read-only.", "Cannot run attack tests or change protection."]];
  return (
    <section className="card table-wrap"><table><thead><tr><th>Role</th><th>Can</th><th>Cannot</th></tr></thead>
      <tbody>{rows.map(([r, c, n]) => <tr key={r}><td><b>{r}</b></td><td>{c}</td><td>{n}</td></tr>)}</tbody></table>
      <p className="muted small">These limits are enforced by the server on every request, not just by hiding buttons. Denied attempts are written to the audit log.</p></section>);
}

export default function Admin() {
  const [tab, setTab] = useState("overview");
  return (
    <>
      <PageHeader title="Admin" subtitle="Manage people, check system health and review security activity." />
      <nav className="admin-tabs" aria-label="Admin sections">{TABS.map(([k, l]) => <button key={k} className={tab === k ? "on" : ""} aria-current={tab === k ? "page" : undefined} onClick={() => setTab(k)}>{l}</button>)}</nav>
      {tab === "overview" && <Overview />}
      {tab === "users" && <Users />}
      {tab === "roles" && <Roles />}
      {tab === "activity" && <Audit embedded />}
      {tab === "system" && <Settings embedded />}
    </>);
}
