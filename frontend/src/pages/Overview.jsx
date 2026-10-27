import { Link } from "react-router-dom";
import { Area, AreaChart, Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { FileText, TriangleAlert, ShieldCheck, Percent, CircleCheck, CircleX, Plus, Server } from "lucide-react";
import { api } from "../services/api";
import { useApi } from "../services/useApi";
import { useAuth } from "../services/auth";
import { Badge, CATEGORY_LABELS, ErrorState, ExecBadge, Loading, SEVERITY_OPTIONS, SeverityBadge, VerdictBadge, fmt } from "../components/ui";

const loadTests = () => api.tests({ limit: 200 });
const TIP = { contentStyle: { background: "#131316", border: "1px solid #26262c", borderRadius: 8 } };
const SHADES = ["#f4f4f5", "#a1a1aa", "#71717a", "#52525b", "#3f3f46"];
const isAttack = (c) => c !== "normal_request";
const pct = (n, d) => (d ? Math.round((n / d) * 100) : null);
const ago = (iso) => {
  const m = Math.max(0, Math.round((Date.now() - new Date(iso)) / 60000));
  return m < 1 ? "just now" : m < 60 ? `${m} min ago` : m < 1440 ? `${Math.round(m / 60)} h ago` : `${Math.round(m / 1440)} d ago`;
};

function lastDays(items, n = 7) {
  const days = [];
  for (let i = n - 1; i >= 0; i--) {
    const d = new Date(); d.setHours(0, 0, 0, 0); d.setDate(d.getDate() - i);
    days.push({ key: d.toDateString(), name: d.toLocaleDateString(undefined, { month: "short", day: "numeric" }), Pass: 0, Fail: 0, Other: 0, Detected: 0, Blocked: 0 });
  }
  for (const t of items) {
    const row = days.find((d) => d.key === new Date(t.created_at).toDateString());
    if (!row) continue;
    if (t.outcome === "PASS") row.Pass++; else if (t.outcome === "FAIL") row.Fail++; else row.Other++;
    if (isAttack(t.category)) { if (t.outcome === "FAIL") row.Detected++; if (t.outcome === "PASS") row.Blocked++; }
  }
  return days;
}

function Donut({ parts, total }) {
  const R = 56, C = 2 * Math.PI * R; let off = 0;
  return (
    <div className="donut">
      <svg viewBox="0 0 140 140" width="150" height="150" role="img" aria-label="Tests by category">
        <circle cx="70" cy="70" r={R} fill="none" stroke="#26262c" strokeWidth="16" />
        {parts.map((p, i) => { const len = (p.value / total) * C; const el = <circle key={p.name} cx="70" cy="70" r={R} fill="none" stroke={SHADES[i % 5]} strokeWidth="16" strokeDasharray={`${len} ${C - len}`} strokeDashoffset={-off} transform="rotate(-90 70 70)" />; off += len; return el; })}
      </svg>
      <div className="donut-c"><div><b>{total}</b><br />Tests</div></div>
    </div>
  );
}

export default function Overview() {
  const { user } = useAuth();
  const dash = useApi(api.dashboard);
  const list = useApi(loadTests);
  const health = useApi(api.health);
  const ai = useApi(api.aiHealth);

  if (dash.loading || list.loading) return <Loading label="Loading dashboard…" />;
  if (dash.error || list.error) return <ErrorState message={dash.error || list.error} onRetry={() => { dash.retry(); list.retry(); health.retry(); ai.retry(); }} />;
  const d = dash.data, items = list.data.items;
  const name = user.email.split("@")[0];
  const days = lastDays(items);
  const rate = d.attack_success_rate == null ? "—" : `${d.attack_success_rate}%`;
  const cats = d.by_category.map((c) => ({ ...c, label: CATEGORY_LABELS[c.category] || c.category, n: c.PASS + c.FAIL + c.NEEDS_REVIEW + c.ERROR }));
  const total = cats.reduce((a, c) => a + c.n, 0);
  const risk = cats.filter((c) => isAttack(c.category) && c.PASS + c.FAIL > 0).map((c) => ({ ...c, asr: pct(c.FAIL, c.PASS + c.FAIL) })).sort((a, b) => b.asr - a.asr);
  const models = Object.values(items.reduce((acc, t) => {
    const k = t.model || "unknown"; const m = (acc[k] ||= { model: k, tests: 0, pass: 0, fail: 0 });
    m.tests++; if (isAttack(t.category)) { if (t.outcome === "PASS") m.pass++; if (t.outcome === "FAIL") m.fail++; } return acc;
  }, {}));
  const backendOk = !health.error && !health.loading, aiOk = ai.data?.ok;
  const base = d.by_mode.baseline, def = d.by_mode.defended;
  const newTo = user.role === "red_team" ? "/red-team" : "/blue-team";
  const kpis = [
    [FileText, d.total_tests, "Total tests"], [TriangleAlert, d.failed, "Vulnerabilities found"],
    [ShieldCheck, def.total, "Defended runs"], [Percent, rate, "Attack success rate"],
  ];
  const Empty = ({ children }) => <div className="empty">{children}</div>;
  return (
    <>
      <div className="d-head">
        <div><h1>Welcome back, <span style={{ textTransform: "capitalize" }}>{name}</span></h1>
          <p className="muted">Monitor, test and secure your AI model against real-world risks. {d.scope_note}.</p></div>
        <Link className="btn primary lg" to={newTo}><Plus size={18} /> New Test</Link>
      </div>

      <section className="d-kpis">
        {kpis.map(([Icon, v, l]) => (
          <div className="card kpi" key={l} title={l === "Attack success rate" ? d.attack_success_note : undefined}>
            <span className="kpi-ico"><Icon size={24} strokeWidth={1.6} /></span>
            <div><div className="kpi-lbl">{l}</div><div className="kpi-val">{v}</div></div>
          </div>
        ))}
        <div className="card">
          <div className="kpi-lbl" style={{ display: "flex", gap: ".5rem", alignItems: "center" }}><Server size={16} /> System status</div>
          <div style={{ marginTop: ".5rem", fontSize: ".9rem", display: "grid", gap: ".25rem" }}>
            <span><span className={`dot ${backendOk ? "online" : "offline"}`} />Backend {backendOk ? "online" : health.loading ? "checking" : "offline"}</span>
            <span><span className={`dot ${aiOk ? "online" : ai.loading ? "checking" : "offline"}`} />AI model {aiOk ? "connected" : ai.loading ? "checking" : "unavailable"}</span>
          </div>
        </div>
      </section>

      <section className="d-row2">
        <div className="card">
          <div className="card-h"><h2>Test Activity</h2><span className="muted small">Last 7 days · up to latest 200 runs</span></div>
          <div className="legend"><span><i style={{ background: "#d4d4d8" }} />Pass</span><span><i style={{ background: "#f87171" }} />Fail</span><span><i style={{ background: "#52525b" }} />Review / error</span></div>
          {d.total_tests === 0 ? <Empty>No tests yet. <Link to={newTo}>Run your first test</Link>.</Empty> : (
            <div className="chart"><ResponsiveContainer width="100%" height="100%"><BarChart data={days}>
              <CartesianGrid stroke="#26262c" vertical={false} /><XAxis dataKey="name" stroke="#9a9aa4" tick={{ fontSize: 11 }} /><YAxis stroke="#9a9aa4" allowDecimals={false} tick={{ fontSize: 11 }} />
              <Tooltip {...TIP} cursor={{ fill: "rgba(255,255,255,.04)" }} />
              <Bar isAnimationActive={false} dataKey="Pass" stackId="a" fill="#d4d4d8" /><Bar isAnimationActive={false} dataKey="Fail" stackId="a" fill="#f87171" /><Bar isAnimationActive={false} dataKey="Other" name="Review / error" stackId="a" fill="#52525b" />
            </BarChart></ResponsiveContainer></div>)}
        </div>
        <div className="card">
          <div className="card-h"><h2>Tests by Category</h2></div>
          {total === 0 ? <Empty>No data yet.</Empty> : (
            <div className="donut-wrap"><Donut parts={cats.map((c) => ({ name: c.label, value: c.n })).filter((p) => p.value)} total={total} />
              <div className="leg-list">{cats.filter((c) => c.n).map((c, i) => <div key={c.category}><span><i style={{ display: "inline-block", width: 9, height: 9, borderRadius: "50%", background: SHADES[i % 5], marginRight: 8 }} />{c.label}</span><b>{pct(c.n, total)}%</b></div>)}</div></div>)}
        </div>
        <div className="card">
          <div className="card-h"><h2>AI Model</h2><Link to="/settings" className="small">Manage</Link></div>
          <div className="prov"><span className="kpi-ico" style={{ width: 44, height: 44 }}><Server size={20} /></span>
            <div style={{ flex: 1 }}><div><span style={{ textTransform: "capitalize" }}>{ai.data?.provider || "Not configured"}</span>{ai.data?.model ? ` · ${ai.data.model}` : ""}</div>
              <div className="small" style={{ color: aiOk ? "var(--teal)" : "var(--red)" }}><span className={`dot ${aiOk ? "online" : "offline"}`} />{aiOk ? "Connected" : "Unavailable"}</div></div></div>
          <p className="muted small" style={{ marginTop: ".6rem" }}>{aiOk ? "Switch provider or model in backend/.env, then restart the backend." : ai.data?.detail || "Set AI_PROVIDER and AI_MODEL in backend/.env."}</p>
        </div>
      </section>

      <section className="d-row3">
        <div className="card">
          <div className="card-h"><h2>Recent Tests</h2><Link to="/history" className="small">View all →</Link></div>
          {d.recent_activity.length === 0 ? <Empty>Nothing yet.</Empty> : (
            <div className="table-wrap"><table>
              <thead><tr><th>Test</th><th>Model</th><th>Category</th><th>Mode</th><th>Execution</th><th>Verdict</th><th>Severity</th><th>Date</th></tr></thead>
              <tbody>{d.recent_activity.map((r) => (
                <tr key={r.test_id}><td><Link to={`/history/${r.test_id}`}>{r.test_name || r.test_id}</Link></td><td>{r.model || "—"}</td><td>{CATEGORY_LABELS[r.category] || r.category}</td><td style={{ textTransform: "capitalize" }}>{r.mode}</td><td><ExecBadge status={r.execution_status} /></td><td><VerdictBadge verdict={r.security_verdict} executionStatus={r.execution_status} /></td><td><SeverityBadge severity={r.severity} /></td><td>{new Date(r.created_at).toLocaleDateString()}</td></tr>
              ))}</tbody></table></div>)}
          {d.by_severity && Object.keys(d.by_severity).length > 0 && (
            <p className="small" aria-label="Results by severity" style={{ marginTop: ".8rem", display: "flex", gap: ".5rem", flexWrap: "wrap", alignItems: "center" }}>
              <span className="muted">By severity:</span>{SEVERITY_OPTIONS.filter((k) => d.by_severity[k]).map((k) => <span key={k}><SeverityBadge severity={k} /> × {d.by_severity[k]}</span>)}
            </p>)}
        </div>
        <div className="card">
          <div className="card-h"><h2>Top Risk Categories</h2><span className="muted small">Attack success rate</span></div>
          {risk.length === 0 ? <Empty>No attack results yet.</Empty> : risk.map((c, i) => (
            <div className="bar-row" key={c.category}><div className="bar-top"><span>{c.label}</span><b>{c.asr}%</b></div>
              <div className="track"><i style={{ width: `${c.asr}%`, background: ["#f87171", "#fb923c", "#a1a1aa", "#71717a", "#52525b"][i % 5] }} /></div></div>))}
        </div>
      </section>

      <section className="d-row4">
        <div className="card">
          <div className="card-h"><h2>Model Results</h2><span className="muted small">Attack tests, latest 200 runs</span></div>
          {models.length === 0 ? <Empty>No results yet.</Empty> : (
            <div className="table-wrap"><table><thead><tr><th>Model</th><th>Tests</th><th>Vulnerabilities</th><th>Attack success</th></tr></thead>
              <tbody>{models.map((m) => <tr key={m.model}><td>{m.model}</td><td>{m.tests}</td><td style={{ color: m.fail ? "var(--red)" : undefined }}>{m.fail}</td><td>{m.pass + m.fail ? `${pct(m.fail, m.pass + m.fail)}%` : "—"}</td></tr>)}</tbody></table></div>)}
        </div>
        <div className="card">
          <div className="card-h"><h2>Vulnerability Trends</h2><span className="muted small">Last 7 days</span></div>
          <div className="legend"><span><i style={{ background: "#f87171" }} />Detected (attack succeeded)</span><span><i style={{ background: "#d4d4d8" }} />Blocked</span></div>
          {d.total_tests === 0 ? <Empty>No data yet.</Empty> : (
            <div className="chart" style={{ height: 170 }}><ResponsiveContainer width="100%" height="100%"><AreaChart data={days}>
              <CartesianGrid stroke="#26262c" vertical={false} /><XAxis dataKey="name" stroke="#9a9aa4" tick={{ fontSize: 10 }} /><YAxis stroke="#9a9aa4" allowDecimals={false} tick={{ fontSize: 10 }} /><Tooltip {...TIP} />
              <Area isAnimationActive={false} type="monotone" dataKey="Detected" stroke="#f87171" fill="#f87171" fillOpacity={0.12} /><Area isAnimationActive={false} type="monotone" dataKey="Blocked" stroke="#d4d4d8" fill="#d4d4d8" fillOpacity={0.08} />
            </AreaChart></ResponsiveContainer></div>)}
        </div>
        <div className="card">
          <div className="card-h"><h2>Baseline vs Defended</h2></div>
          {base.total > 0 && def.total > 0 ? (
            <>{[["Baseline", base], ["Defended", def]].map(([l, m]) => (
              <div className="bar-row" key={l}><div className="bar-top"><span>{l} · {m.total} tests</span><b>{m.attack_success_rate == null ? "—" : `${m.attack_success_rate}%`}</b></div>
                <div className="track"><i style={{ width: `${m.attack_success_rate || 0}%`, background: l === "Baseline" ? "#f87171" : "#34d399" }} /></div></div>))}
              <p className="muted small">Attack success rate over all saved runs. For a like-for-like comparison use the <Link to="/blue-team">Blue Team Console</Link>.</p></>
          ) : <Empty>Run a suite with and without defenses to compare. {user.role !== "red_team" && <Link to="/blue-team">Open Blue Team Console</Link>}</Empty>}
          <div className="feed" style={{ marginTop: ".8rem" }}>
            {d.recent_activity.slice(0, 3).map((r) => (
              <div key={r.test_id}>{r.outcome === "PASS" ? <CircleCheck size={18} color="#34d399" /> : <CircleX size={18} color={r.outcome === "FAIL" ? "#f87171" : "#9a9aa4"} />}<span>{r.test_name || r.test_id}</span><span className="t">{ago(r.created_at)}</span></div>))}
          </div>
        </div>
      </section>
    </>
  );
}
