import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../services/api";
import { useAuth } from "../services/auth";
import { Shield, FileText, ShieldCheck, Layers, ShieldPlus, Play } from "lucide-react";
import { CATEGORY_LABELS, ErrorState, Loading, SeverityBadge, VerdictBadge, fmt } from "../components/ui";
import { CompareBars, Donut, TrendChart, lastDays } from "../components/teamViz";
import RedTeamFindings from "../components/RedTeamFindings";
import ProtectionWizard from "../components/ProtectionWizard";

const BLUES = ["#3b82f6", "#60a5fa", "#2563eb", "#93c5fd", "#1e40af"];

const RULES = [
  ["input_screen", "Input screen", "Blocks prompts matching known override / unrestricted-mode / secret-extraction patterns before the model sees them. Easy to evade with paraphrasing."],
  ["hardened_prompt", "Hardened system prompt", "Adds an instruction-hierarchy policy (plus your policy text) to the system prompt. Effect depends on the model."],
  ["output_redaction", "Output safety check", "Redacts registered synthetic secrets from responses; withholds responses that contain them reversed or base64-encoded."],
  ["output_contract", "Output contract enforcement", "Enforces explicit uppercase-only and literal end-token requirements from trusted system instructions after output redaction."],
];
const pct = (v) => (v == null ? "—" : `${v}%`);

export default function BlueTeam() {
  const { user } = useAuth();
  const canEdit = user.role === "blue_team";
  const [cfg, setCfg] = useState(null);       // { active, history }
  const [error, setError] = useState("");
  const [cmp, setCmp] = useState(null);
  const [tab, setTab] = useState("play");
  const [dash, setDash] = useState(null);
  const [recent, setRecent] = useState([]);

  const load = useCallback(async () => {
    setError("");
    try {
      const c = await api.defenseConfig();
      setCfg(c);
      setCmp(await api.latestComparison());
      api.dashboard().then(setDash).catch(() => {});
      api.tests({ limit: 200 }).then((d) => setRecent(d.items)).catch(() => {});
    } catch (e) { setError(e.message); }
  }, []);
  useEffect(() => { load(); }, [load]);

  if (!cfg && !error) return <Loading label="Loading defense settings…" />;
  const active = cfg?.active;
  const enabled = active ? RULES.filter(([k]) => active[k]).length : 0;
  const days = lastDays(recent.filter((t) => t.mode === "defended"));
  const SHORT = { input_screen: "Input screen", hardened_prompt: "Hardened prompt", output_redaction: "Output check", output_contract: "Output contract" };
  const rows = (cfg?.history || []);
  const ConfigTable = ({ limit }) => rows.length === 0 ? <div className="empty">No configuration saved yet.</div> : (
    <div className="table-wrap"><table>
      <thead><tr><th>Version</th><th>Mechanisms</th><th>Effectiveness</th><th>Status</th><th>Saved by</th><th>Date</th></tr></thead>
      <tbody>{rows.slice(0, limit).map((h) => {
        const eff = cmp && cmp.defense_config_id === h.id ? cmp.defense_effectiveness : null;
        return (
          <tr key={h.id}><td>v{h.id}</td><td>{RULES.filter(([k]) => h[k]).map(([k]) => SHORT[k]).join(" · ") || "None"}</td>
            <td>{eff == null ? "—" : <span className="eff">{eff}% <span className="track"><i style={{ width: `${eff}%`, background: "#3b82f6" }} /></span></span>}</td>
            <td><span className={`badge ${h.is_active ? "passed" : "err"}`}>{h.is_active ? "Active" : "Inactive"}</span></td><td>{h.created_by || "—"}</td><td>{new Date(h.created_at).toLocaleDateString()}</td></tr>);
      })}</tbody></table></div>);
  return (
    <div className="team team-blue">
      <header className="team-hero">
        <Shield size={44} strokeWidth={1.5} color="var(--accent)" />
        <div><h1>Blue Team</h1><p>Choose protection, apply it, test it, and see what still needs fixing.</p></div>
      </header>
      <section className="team-kpis">
        {[[FileText, dash?.total_tests ?? "—", "Tests run"], [ShieldCheck, dash?.by_mode?.defended?.total ?? "—", "Defended runs"], [Layers, `${enabled}/${RULES.length}`, "Defense mechanisms on"]].map(([I, v, l]) => (
          <div className="team-kpi" key={l}><span className="team-ico"><I size={24} strokeWidth={1.6} /></span><div><b>{v}</b><span>{l}</span></div></div>
        ))}
      </section>
      <nav className="team-tabs" aria-label="Blue Team sections">
        {[["play", "Protect & Test"], ["findings", "Red Team Findings"], ["cmp", "Comparison"], ["cfgs", "Saved Configurations"]].map(([k, l]) => <button key={k} className={tab === k ? "on" : ""} onClick={() => setTab(k)}>{l}</button>)}
        <Link to="/history">Test History</Link>
      </nav>
      {!canEdit && <div className="demo-banner">Read-only: administrators can review the configuration but not change it.</div>}
      {error && <ErrorState message={error} onRetry={load} />}

      {tab === "play" && <ProtectionWizard cfg={cfg} cmp={cmp} canEdit={canEdit} onApplied={load}
        onCompared={(c) => { setCmp(c); api.dashboard().then(setDash).catch(() => {}); api.tests({ limit: 200 }).then((d) => setRecent(d.items)).catch(() => {}); }} />}

      {tab === "findings" && <RedTeamFindings canRetest={canEdit} hasConfig={!!active} />}
      {tab === "cmp" && (cmp ? <Comparison c={cmp} /> : <div className="team-panel"><p className="muted">No comparison has been run yet. Open the Protect & Test tab to run one.</p></div>)}
      {tab === "cfgs" && <section className="team-panel"><h2>Saved Configurations</h2><ConfigTable limit={50} /></section>}
    </div>
  );
}

function Comparison({ c }) {
  const rows = [
    ["Total tests", c.baseline.total, c.defended.total],
    ["Pass", c.baseline.PASS, c.defended.PASS],
    ["Fail", c.baseline.FAIL, c.defended.FAIL],
    ["Needs review", c.baseline.NEEDS_REVIEW, c.defended.NEEDS_REVIEW],
    ["Error", c.baseline.ERROR, c.defended.ERROR],
    ["Successful attacks (confirmed Fail)", c.baseline.attack_successes, c.defended.attack_successes],
    ["Attack success rate", pct(c.baseline.attack_success_rate), pct(c.defended.attack_success_rate)],
    ["False refusals (harmless requests refused)", c.baseline.false_refusals, c.defended.false_refusals],
    ["False refusal rate", pct(c.baseline.false_refusal_rate), pct(c.defended.false_refusal_rate)],
  ];
  return (
    <>
      <section className="stats">
        <div className="card stat" title={c.effectiveness_formula}>
          <div className="stat-value">{pct(c.defense_effectiveness)}</div><div className="muted">Defense effectiveness</div>
        </div>
        <div className="card stat"><div className="stat-value">{c.remaining_failures.length}</div><div className="muted">Remaining failures</div></div>
        <div className="card stat"><div className="stat-value small">{c.baseline_group_id}</div><div className="muted">Baseline run</div></div>
        <div className="card stat"><div className="stat-value small">{c.defended_group_id}</div><div className="muted">Defended run (config v{c.defense_config_id})</div></div>
      </section>
      {c.caveats.map((t) => <div className="demo-banner" key={t}>{t}</div>)}
      <section className="card table-wrap">
        <table className="metric-table">
          <thead><tr><th>Metric</th><th>Baseline</th><th>Defended</th></tr></thead>
          <tbody>{rows.map(([m, b, d]) => <tr key={m}><td>{m}</td><td>{b}</td><td>{d}</td></tr>)}</tbody>
        </table>
        <p className="muted">Effectiveness = {c.effectiveness_formula}. Computed from saved outcomes; NEEDS_REVIEW and ERROR are never counted as successful attacks.</p>
      </section>
      <section className="card">
        <h2>Remaining failures</h2>
        {c.remaining_failures.length === 0 ? <p className="muted">No confirmed successful attacks in the defended run. This does not prove the system is secure; the suite is small.</p> : (
          <ul>{c.remaining_failures.map((r) => <li key={r.test_id}><Link to={`/history/${r.test_id}`}>{r.test_name}</Link> <SeverityBadge severity={r.severity} /> <span className="muted">({CATEGORY_LABELS[r.category]})</span>: {r.explanation}</li>)}</ul>
        )}
      </section>
      <section className="card table-wrap">
        <h2>Per-test results</h2>
        <table className="metric-table">
          <thead><tr><th>Test</th><th>Baseline verdict</th><th>Baseline severity</th><th>Defended verdict</th><th>Defended severity</th><th>Defense triggered</th></tr></thead>
          <tbody>{c.per_test.map((p) => <tr key={p.test_case_id}><td>{p.test_name}</td><td><VerdictBadge verdict={p.baseline_outcome === "ERROR" ? null : p.baseline_outcome} executionStatus={p.baseline_outcome === "ERROR" ? "ERROR" : "COMPLETED"} /></td><td><SeverityBadge severity={p.baseline_severity} /></td><td><VerdictBadge verdict={p.defended_outcome === "ERROR" ? null : p.defended_outcome} executionStatus={p.defended_outcome === "ERROR" ? "ERROR" : "COMPLETED"} /></td><td><SeverityBadge severity={p.defended_severity} /></td><td>{p.defense_triggered ? "Yes" : "No"}</td></tr>)}</tbody>
        </table>
      </section>
    </>
  );
}
