import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../services/api";
import { useAuth } from "../services/auth";
import { Shield, FileText, ShieldCheck, Layers, ShieldPlus, Play } from "lucide-react";
import { CATEGORY_LABELS, ErrorState, Loading, fmt } from "../components/ui";
import { CompareBars, Donut, TrendChart, lastDays } from "../components/teamViz";

const BLUES = ["#3b82f6", "#60a5fa", "#2563eb", "#93c5fd", "#1e40af"];

const DEFAULTS = { name: "Blue Team policy", input_screen: true, hardened_prompt: true, output_redaction: true, policy_text: "" };
const RULES = [
  ["input_screen", "Input screen", "Blocks prompts matching known override / unrestricted-mode / secret-extraction patterns before the model sees them. Easy to evade with paraphrasing."],
  ["hardened_prompt", "Hardened system prompt", "Adds an instruction-hierarchy policy (plus your policy text) to the system prompt. Effect depends on the model."],
  ["output_redaction", "Output safety check", "Redacts registered synthetic secrets from responses; withholds responses that contain them reversed or base64-encoded."],
];
const pct = (v) => (v == null ? "—" : `${v}%`);

export default function BlueTeam() {
  const { user } = useAuth();
  const canEdit = user.role === "blue_team";
  const [cfg, setCfg] = useState(null);       // { active, history }
  const [draft, setDraft] = useState(DEFAULTS);
  const [error, setError] = useState("");
  const [msg, setMsg] = useState("");
  const [saving, setSaving] = useState(false);
  const [running, setRunning] = useState(false);
  const [cmp, setCmp] = useState(null);
  const [tab, setTab] = useState("play");
  const [dash, setDash] = useState(null);
  const [recent, setRecent] = useState([]);

  const load = useCallback(async () => {
    setError("");
    try {
      const c = await api.defenseConfig();
      setCfg(c);
      if (c.active) setDraft({ name: c.active.name, input_screen: c.active.input_screen, hardened_prompt: c.active.hardened_prompt, output_redaction: c.active.output_redaction, policy_text: c.active.policy_text });
      setCmp(await api.latestComparison());
      api.dashboard().then(setDash).catch(() => {});
      api.tests({ limit: 200 }).then((d) => setRecent(d.items)).catch(() => {});
    } catch (e) { setError(e.message); }
  }, []);
  useEffect(() => { load(); }, [load]);

  async function save() {
    setSaving(true); setMsg(""); setError("");
    try {
      const saved = await api.saveDefenseConfig(draft);
      setMsg(`Saved as version ${saved.id}. The backend now applies it to every defended test.`);
      await load();
    } catch (e) { setError(e.message); } finally { setSaving(false); }
  }
  async function compare() {
    setRunning(true); setMsg(""); setError("");
    try { setCmp(await api.runComparison()); api.dashboard().then(setDash).catch(() => {}); api.tests({ limit: 200 }).then((d) => setRecent(d.items)).catch(() => {}); } catch (e) { setError(e.message); } finally { setRunning(false); }
  }

  if (!cfg && !error) return <Loading label="Loading defense settings…" />;
  const active = cfg?.active;
  const dirty = active && JSON.stringify(draft) !== JSON.stringify({ name: active.name, input_screen: active.input_screen, hardened_prompt: active.hardened_prompt, output_redaction: active.output_redaction, policy_text: active.policy_text });
  const enabled = active ? RULES.filter(([k]) => active[k]).length : 0;
  const days = lastDays(recent.filter((t) => t.mode === "defended"));
  const SHORT = { input_screen: "Input screen", hardened_prompt: "Hardened prompt", output_redaction: "Output check" };
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
        <div><h1>Blue Team</h1><p>Defend AI systems with safety measures and evaluate their effectiveness.</p></div>
      </header>
      <section className="team-kpis">
        {[[FileText, dash?.total_tests ?? "—", "Tests run"], [ShieldCheck, dash?.by_mode?.defended?.total ?? "—", "Defended runs"], [Layers, `${enabled}/${RULES.length}`, "Defense mechanisms on"]].map(([I, v, l]) => (
          <div className="team-kpi" key={l}><span className="team-ico"><I size={24} strokeWidth={1.6} /></span><div><b>{v}</b><span>{l}</span></div></div>
        ))}
      </section>
      <nav className="team-tabs" aria-label="Blue Team sections">
        {[["play", "Defense Playground"], ["cmp", "Comparison"], ["cfgs", "Saved Configurations"]].map(([k, l]) => <button key={k} className={tab === k ? "on" : ""} onClick={() => setTab(k)}>{l}</button>)}
        <Link to="/history">Test History</Link>
      </nav>
      {!canEdit && <div className="demo-banner">Read-only: administrators can review the configuration but not change it.</div>}
      {error && <ErrorState message={error} onRetry={load} />}

      {tab === "play" && (
        <>
          <section className="team-grid">
            <div className="team-panel form">
              <h2>Configure Defense</h2>
              <div className="switches">
                {RULES.map(([key, label, hint]) => (
                  <div key={key}>
                    <label className="toggle"><input type="checkbox" disabled={!canEdit} checked={draft[key]} onChange={(e) => setDraft({ ...draft, [key]: e.target.checked })} /> {label}</label>
                    <p className="hint">{hint}</p>
                  </div>
                ))}
              </div>
              <label htmlFor="policy">Additional policy text (used with the hardened prompt)</label>
              <textarea id="policy" rows={4} maxLength={1000} disabled={!canEdit} value={draft.policy_text} onChange={(e) => setDraft({ ...draft, policy_text: e.target.value })} placeholder="e.g. Never discuss pricing." />
              <div className="muted small" style={{ textAlign: "right" }}>{draft.policy_text.length}/1000</div>
              {canEdit && <div><button className="btn accent" disabled={saving} onClick={save}><ShieldPlus size={15} /> {saving ? "Saving…" : "Save configuration"}</button></div>}
              {msg && <p role="status" style={{ color: "var(--teal)" }}>{msg}</p>}
            </div>
            <div className="team-panel">
              <h2>Current Configuration {cmp && <span className="team-chip">Effectiveness {pct(cmp.defense_effectiveness)}</span>}</h2>
              {active ? (
                <dl>
                  <dt>Version</dt><dd>{active.id} · saved {fmt(active.created_at)} by {active.created_by || "—"}</dd>
                  {RULES.map(([k, label]) => (<span key={k}><dt>{label}</dt><dd>{active[k] ? "On" : "Off"}</dd></span>))}
                  <dt>Policy text</dt><dd>{active.policy_text || "(none)"}</dd>
                  {dirty && <p className="muted">You have unsaved changes. Comparisons use the saved version above.</p>}
                </dl>
              ) : <p className="muted">No configuration saved yet. Defended runs are unavailable until a Blue Team user saves one.</p>}
              <h2 style={{ marginTop: "1rem" }}>Baseline versus defended</h2>
              <p className="muted small">Runs the same 11 predefined tests twice against the real model: first with defenses off, then with the saved configuration. Results are saved to the database.</p>
              {canEdit && <div className="row"><button className="btn accent" disabled={running || !active} onClick={compare}><Play size={15} /> {running ? "Running comparison…" : "Run comparison"}</button></div>}
              {running && <p className="muted small" role="status">Running 22 tests one by one. A local model can take several minutes.</p>}
              {!active && canEdit && <p className="muted small">Save a configuration first.</p>}
              {cmp && <p className="small"><Link to="#" onClick={(e) => { e.preventDefault(); setTab("cmp"); }}>See full comparison →</Link></p>}
            </div>
          </section>
          <section className="team-panel">
            <div className="card-h"><h2>Recent Blue Team Defenses</h2><button className="linklike" onClick={() => setTab("cfgs")}>View all →</button></div>
            <ConfigTable limit={5} />
          </section>
          <section className="team-grid">
            <div className="team-panel"><h2>Defended Outcomes</h2>
              {cmp ? <Donut label="Tests" colors={["#3b82f6", "#60a5fa", "#93c5fd", "#1e40af"]} parts={[["Pass", cmp.defended.PASS], ["Fail", cmp.defended.FAIL], ["Needs review", cmp.defended.NEEDS_REVIEW], ["Error", cmp.defended.ERROR]].map(([name, value]) => ({ name, value }))} /> : <div className="empty">Run a comparison to see results.</div>}</div>
            <div className="team-panel"><h2>{cmp ? "Baseline vs Defended" : "Defended Attack Trend"}</h2>
              {cmp ? <CompareBars aColor="#71717a" bColor="#3b82f6" data={[["Pass", "PASS"], ["Fail", "FAIL"], ["Review", "NEEDS_REVIEW"], ["Error", "ERROR"]].map(([name, k]) => ({ name, Baseline: cmp.baseline[k], Defended: cmp.defended[k] }))} />
                : <TrendChart data={days} aKey="Detected" bKey="Blocked" aColor="#60a5fa" bColor="#93c5fd" aLabel="Detected" bLabel="Blocked" />}</div>
          </section>
        </>
      )}

      {tab === "cmp" && (cmp ? <Comparison c={cmp} /> : <div className="team-panel"><p className="muted">No comparison has been run yet. Open the Defense Playground tab to run one.</p></div>)}
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
          <ul>{c.remaining_failures.map((r) => <li key={r.test_id}><Link to={`/history/${r.test_id}`}>{r.test_name}</Link> <span className="muted">({CATEGORY_LABELS[r.category]})</span>: {r.explanation}</li>)}</ul>
        )}
      </section>
      <section className="card table-wrap">
        <h2>Per-test results</h2>
        <table className="metric-table">
          <thead><tr><th>Test</th><th>Baseline</th><th>Defended</th><th>Defense triggered</th></tr></thead>
          <tbody>{c.per_test.map((p) => <tr key={p.test_case_id}><td>{p.test_name}</td><td>{p.baseline_outcome}</td><td>{p.defended_outcome}</td><td>{p.defense_triggered ? "Yes" : "No"}</td></tr>)}</tbody>
        </table>
      </section>
    </>
  );
}
