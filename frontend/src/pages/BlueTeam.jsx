import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../services/api";
import { useAuth } from "../services/auth";
import { CATEGORY_LABELS, ErrorState, Loading, PageHeader, fmt } from "../components/ui";

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

  const load = useCallback(async () => {
    setError("");
    try {
      const c = await api.defenseConfig();
      setCfg(c);
      if (c.active) setDraft({ name: c.active.name, input_screen: c.active.input_screen, hardened_prompt: c.active.hardened_prompt, output_redaction: c.active.output_redaction, policy_text: c.active.policy_text });
      setCmp(await api.latestComparison());
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
    try { setCmp(await api.runComparison()); } catch (e) { setError(e.message); } finally { setRunning(false); }
  }

  if (!cfg && !error) return <Loading label="Loading defense settings…" />;
  const active = cfg?.active;
  const dirty = active && JSON.stringify(draft) !== JSON.stringify({ name: active.name, input_screen: active.input_screen, hardened_prompt: active.hardened_prompt, output_redaction: active.output_redaction, policy_text: active.policy_text });
  return (
    <>
      <PageHeader title="Blue Team Console" subtitle="Configure defenses enforced by the backend, then compare the same test suite with and without them." />
      {!canEdit && <div className="demo-banner">Read-only: administrators can review the configuration but not change it.</div>}
      {error && <ErrorState message={error} onRetry={load} />}
      <section className="grid2">
        <div className="card form">
          <h2>Safety policy</h2>
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
          {canEdit && <div><button className="btn primary" disabled={saving} onClick={save}>{saving ? "Saving…" : "Save configuration"}</button></div>}
          {msg && <p role="status" style={{ color: "var(--teal)" }}>{msg}</p>}
        </div>
        <div className="card">
          <h2>Current configuration</h2>
          {active ? (
            <dl>
              <dt>Version</dt><dd>{active.id} · saved {fmt(active.created_at)} by {active.created_by || "—"}</dd>
              {RULES.map(([k, label]) => (<span key={k}><dt>{label}</dt><dd>{active[k] ? "On" : "Off"}</dd></span>))}
              <dt>Policy text</dt><dd>{active.policy_text || "(none)"}</dd>
              {dirty && <p className="muted">You have unsaved changes. Comparisons use the saved version above.</p>}
            </dl>
          ) : <p className="muted">No configuration saved yet. Defended runs are unavailable until a Blue Team user saves one.</p>}
        </div>
      </section>

      <section className="card">
        <h2>Baseline versus defended</h2>
        <p className="muted">Runs the same 11 predefined tests twice against the real model: first with defenses off, then with the saved configuration. Results are saved to the database.</p>
        {canEdit && <div className="row"><button className="btn primary" disabled={running || !active} onClick={compare}>{running ? "Running comparison…" : "Run comparison"}</button></div>}
        {running && <p className="muted" role="status">Running 22 tests one by one. A local model can take several minutes.</p>}
        {!active && canEdit && <p className="muted">Save a configuration first.</p>}
      </section>

      {cmp ? <Comparison c={cmp} /> : active && <div className="card"><p className="muted">No comparison has been run yet.</p></div>}
    </>
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
