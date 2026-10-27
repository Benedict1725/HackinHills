import { useEffect, useMemo, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { CheckCircle2, Play, ShieldPlus, TriangleAlert } from "lucide-react";
import { api } from "../services/api";
import { CATEGORY_LABELS, SeverityBadge, fmt } from "./ui";

const MECHS = [
  ["input_screen", "Input Screen", "Blocks prompts that match known attack phrasing before the AI sees them.",
    "Matches configured override, unrestricted-mode and secret-extraction patterns. Easy to evade with paraphrasing, so it is one layer, not a guarantee."],
  ["hardened_prompt", "Hardened System Prompt", "Tells the AI which instructions to trust, plus any rules you add.",
    "Adds an instruction-hierarchy policy (and your policy text) to the system prompt. How well it works depends on the model."],
  ["output_redaction", "Output Safety Check", "Looks at every answer and removes protected secrets before it is shown.",
    "Redacts registered synthetic secrets; withholds answers that contain them reversed or base64-encoded."],
  ["output_contract", "Output Format Rules", "Enforces simple format rules (such as uppercase only) the system prompt asks for.",
    "Enforces explicit uppercase-only and literal end-token requirements from trusted system instructions, after output redaction."],
];
const KEYS = MECHS.map(([k]) => k);
const same = (a, b) => KEYS.every((k) => !!a[k] === !!b[k]) && (a.policy_text || "") === (b.policy_text || "");
const Step = ({ n, title, done, children }) => (
  <section className="team-panel wizard-step" aria-labelledby={`step-${n}`}>
    <h2 id={`step-${n}`}><span className={`step-n ${done ? "done" : ""}`}>{done ? <CheckCircle2 size={16} /> : n}</span> {title}</h2>
    {children}
  </section>
);

export default function ProtectionWizard({ cfg, cmp, canEdit, onApplied, onCompared }) {
  const active = cfg?.active;
  const [presets, setPresets] = useState([]);
  const [preset, setPreset] = useState("recommended");
  const [draft, setDraft] = useState({ input_screen: true, hardened_prompt: true, output_redaction: true, output_contract: false, policy_text: "" });
  const [saving, setSaving] = useState(false), [running, setRunning] = useState(false);
  const [notice, setNotice] = useState(""), [err, setErr] = useState(""), [advanced, setAdvanced] = useState(false);
  const lock = useRef(false);   // synchronous guard: a double click can never start two runs

  useEffect(() => { api.presets().then((d) => setPresets(d.presets)).catch((e) => setErr(`Could not load protection presets: ${e.message}`)); }, []);
  const matching = (c) => presets.find((p) => KEYS.every((k) => !!p[k] === !!c[k]))?.id;
  useEffect(() => {   // reflect what the backend says is active (never what we merely clicked)
    if (active) { setDraft({ ...Object.fromEntries(KEYS.map((k) => [k, !!active[k]])), policy_text: active.policy_text || "" }); setPreset(matching(active) && !active.policy_text ? matching(active) : "custom"); }
  }, [active?.id, presets.length]); // eslint-disable-line react-hooks/exhaustive-deps

  const dirty = !active || !same(draft, active);
  const activeName = active ? (presets.find((p) => KEYS.every((k) => !!p[k] === !!active[k]))?.label || "Custom") : null;
  function choose(p) { setPreset(p.id); setDraft({ ...Object.fromEntries(KEYS.map((k) => [k, p[k]])), policy_text: draft.policy_text }); setNotice(""); }
  function toggle(k, v) { setDraft({ ...draft, [k]: v }); setPreset("custom"); setNotice(""); }

  async function apply() {
    if (lock.current) return; lock.current = true; setSaving(true); setErr(""); setNotice("");
    try {
      const label = presets.find((p) => p.id === preset)?.label || "Custom";
      const saved = await api.saveDefenseConfig({ name: `${label} protection`, ...Object.fromEntries(KEYS.map((k) => [k, draft[k]])), policy_text: draft.policy_text });
      await onApplied();     // re-reads the backend; the banner below is driven by that, not by this click
      setNotice(`Protection saved by the server as version ${saved.id}.`);
    } catch (e) { setErr(`Protection was NOT applied: ${e.message}`); } finally { setSaving(false); lock.current = false; }
  }
  async function runTest() {
    if (lock.current) return; lock.current = true; setRunning(true); setErr(""); setNotice("");
    try { onCompared(await api.runComparison()); } catch (e) { setErr(`The security test did not finish: ${e.message}`); } finally { setRunning(false); lock.current = false; }
  }
  const busy = saving || running;
  const stale = cmp && active && cmp.defense_config_id !== active.id;
  return (
    <div className="wizard">
      {err && <div className="state error" role="alert"><p>{err}</p></div>}
      <Step n={1} title="Choose protection" done={!!active}>
        <p className="muted small">Pick how much protection to apply. Each level is a fixed set of the four safeguards below. None of them guarantees security.</p>
        <div className="preset-grid" role="radiogroup" aria-label="Protection level">
          {presets.map((p) => (
            <label key={p.id} className={`preset ${preset === p.id ? "on" : ""}`}>
              <input type="radio" name="preset" value={p.id} checked={preset === p.id} disabled={!canEdit || busy} onChange={() => choose(p)} />
              <b>{p.label}</b>{p.id === "recommended" && <span className="team-chip">Default</span>}
              <span className="small">{p.summary}</span>
              <span className="small muted">{MECHS.filter(([k]) => p[k]).map(([, n]) => n).join(" · ")}</span>
            </label>))}
        </div>
        <details className="advanced" open={advanced} onToggle={(e) => setAdvanced(e.target.open)}>
          <summary>Advanced settings {preset === "custom" && <span className="team-chip">Custom</span>}</summary>
          <div className="switches">
            {MECHS.map(([k, name, one, tech]) => (
              <div key={k}>
                <label className="toggle"><input type="checkbox" disabled={!canEdit || busy} checked={!!draft[k]} onChange={(e) => toggle(k, e.target.checked)} /> {name} <span className={`badge ${draft[k] ? "passed" : "na"}`}>{draft[k] ? "On" : "Off"}</span></label>
                <p className="hint">{one}</p>
                <details className="tech"><summary>How it works</summary><p className="hint">{tech}</p></details>
              </div>))}
          </div>
          <label htmlFor="policy">Extra rules for the AI <span className="muted small">(used with the Hardened System Prompt)</span></label>
          <textarea id="policy" rows={3} maxLength={1000} disabled={!canEdit || busy} value={draft.policy_text} onChange={(e) => { setDraft({ ...draft, policy_text: e.target.value }); setPreset("custom"); }} placeholder="e.g. Never discuss pricing." />
        </details>
      </Step>

      <Step n={2} title="Apply protection" done={!!active && !dirty}>
        {canEdit ? <button className="btn accent big" disabled={busy || !dirty} onClick={apply}><ShieldPlus size={16} /> {saving ? "Applying…" : dirty ? "Apply Protection" : "Protection applied"}</button>
          : <p className="muted">Read-only: administrators can review protection but not change it.</p>}
        {active ? (
          <p className="small" role="status"><span className="dot online" /> <b>Active on the server:</b> {activeName} (version {active.id}, saved {fmt(active.created_at)} by {active.created_by || "—"}).
            {" "}{MECHS.filter(([k]) => active[k]).map(([, n]) => n).join(", ") || "No safeguards on"}.{dirty && <> <b>You have changes that are not applied yet.</b></>}</p>
        ) : <p className="muted small"><span className="dot offline" /> No protection is active yet. Choose a level and press Apply Protection.</p>}
        {notice && <p role="status" style={{ color: "var(--teal)" }}>{notice}</p>}
        {active && cmp && <p className="hint"><TriangleAlert size={13} /> Changing protection changes how the next results are produced. Earlier results stay saved and are labelled with the version they used, so compare like with like.</p>}
      </Step>

      <Step n={3} title="Run security test" done={!!cmp && !stale}>
        <p className="muted small">Runs the same 11 predefined attacks twice against the real AI: once with no protection, then with your active protection. Results are saved.</p>
        <button className="btn accent big" disabled={busy || !active || dirty || !canEdit} onClick={runTest}><Play size={16} /> {running ? "Testing your protection…" : "Test My Protection"}</button>
        {!active && <p className="muted small">Apply protection first.</p>}
        {active && dirty && <p className="muted small">Apply your changes first so the test uses what you see here.</p>}
        {running && <p className="muted small" role="status">Running 22 tests one at a time. A local model can take several minutes. Please keep this page open.</p>}
      </Step>

      <Step n={4} title="Review results" done={!!cmp}>
        {!cmp ? <div className="empty">No results yet. After Step 3 finishes you will see what was blocked and what still needs fixing.</div> : <Results c={cmp} stale={stale} />}
      </Step>
    </div>
  );
}

function Results({ c, stale }) {
  const complete = c.baseline.ERROR === 0 && c.defended.ERROR === 0;
  const base = c.baseline.attack_successes, left = c.defended.attack_successes;
  const stopped = Math.max(0, base - left);
  const unresolved = c.per_test.filter((p) => p.defended_outcome === "NEEDS_REVIEW").length;
  const [open, setOpen] = useState({});
  const tiles = [["Tests completed", `${c.defended.total - c.defended.ERROR} of ${c.defended.total}`], ["Attacks that worked with no protection", base], ["Attacks stopped by protection", stopped], ["Attacks that still work", left]];
  return (
    <>
      {stale && <div className="demo-banner">These results used an earlier protection version (v{c.defense_config_id}), not the one that is active now.</div>}
      {!complete && <div className="demo-banner" role="alert">Incomplete: {c.baseline.ERROR + c.defended.ERROR} test(s) could not run (model or connection problem). Totals below only count tests that finished.</div>}
      {c.caveats.map((t) => <div className="demo-banner" key={t}>{t}</div>)}
      <div className="stats">{tiles.map(([l, v]) => <div className="card stat" key={l}><div className="stat-value">{v}</div><div className="muted">{l}</div></div>)}</div>
      <p className="small" role="status">{base === 0 ? "No attack worked against the unprotected AI in this run, so there is nothing for protection to improve yet. This is not proof of security."
        : left === 0 ? `Protection stopped all ${base} attack(s) that worked without it in this suite. This does not mean the AI is secure; the suite is small.`
        : `${left} of ${base} attack(s) still work with protection on.`}{unresolved ? ` ${unresolved} defended result(s) need a person to review and are not counted as stopped.` : ""}</p>
      <p className="muted small">Compared with an earlier run: not available yet. Only the latest comparison is stored for display; older runs remain in Test History.</p>

      <h3>What should I fix next?</h3>
      {c.remaining_failures.length === 0 ? <p className="muted">No confirmed failures remain in this run. {unresolved ? "Review the items marked “Needs review” below." : ""}</p> : (
        <ol className="fixlist">{c.remaining_failures.map((r) => (
          <li key={r.test_id}><Link to={`/history/${r.test_id}`}>{r.test_name}</Link> <SeverityBadge severity={r.severity} /> <span className="muted small">({CATEGORY_LABELS[r.category]})</span>
            <div className="small">{r.explanation}</div></li>))}</ol>)}

      <h3>Every test</h3>
      <div className="table-wrap"><table className="metric-table">
        <thead><tr><th>Test</th><th>Without protection</th><th>With protection</th><th></th></tr></thead>
        <tbody>{c.per_test.map((p) => {
          const word = (o) => (o === "FAIL" ? "Attack worked" : o === "PASS" ? "Attack stopped" : o === "NEEDS_REVIEW" ? "Needs review" : o === "ERROR" ? "Did not run" : o === "NOT_APPLICABLE" ? "n/a" : o);
          return (<tr key={p.test_case_id}><td>{p.test_name}<div className="muted small">{CATEGORY_LABELS[p.category]}</div></td>
            <td><span className={`badge ${p.baseline_outcome === "FAIL" ? "failed" : p.baseline_outcome === "PASS" ? "passed" : "na"}`}>{word(p.baseline_outcome)}</span></td>
            <td><span className={`badge ${p.defended_outcome === "FAIL" ? "failed" : p.defended_outcome === "PASS" ? "passed" : p.defended_outcome === "ERROR" ? "exec-err" : "review"}`}>{word(p.defended_outcome)}</span></td>
            <td><button className="linklike" aria-expanded={!!open[p.test_case_id]} onClick={() => setOpen({ ...open, [p.test_case_id]: !open[p.test_case_id] })}>{open[p.test_case_id] ? "Hide" : "Details"}</button>
              {open[p.test_case_id] && <div className="small muted" style={{ marginTop: ".4rem" }}>Defense triggered: {p.defense_triggered ? "yes" : "no"} · Severity without protection: {p.baseline_severity ?? "—"} · with protection: {p.defended_severity ?? "—"}</div>}</td></tr>);
        })}</tbody></table></div>
    </>
  );
}
