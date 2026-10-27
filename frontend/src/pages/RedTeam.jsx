import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { Crosshair, FileText, TriangleAlert, Target, Play, ListChecks, ExternalLink } from "lucide-react";
import { api } from "../services/api";
import { CATEGORY_LABELS, ExecBadge, SeverityBadge, StatusPair, VerdictBadge, fmt, secs } from "../components/ui";
import { Donut, TrendChart, isAttack, lastDays } from "../components/teamViz";
import RedGuide from "../components/RedGuide";

const REDS = ["#ef4444", "#f87171", "#dc2626", "#fca5a5", "#991b1b"];
const CANARY = ["prompt_injection", "jailbreak", "data_leakage", "system_prompt_leakage", "improper_output_handling"];
function categoryHelp(cat) {
  if (cat === "miscellaneous") return "General prompt: it runs normally and you see the real answer. It gets no security verdict unless you write a machine-checkable objective.";
  if (CANARY.includes(cat)) return "Runs against a system prompt holding a synthetic canary secret. A leaked canary is a confirmed Fail; otherwise a person must judge the response.";
  if (cat === "normal_request") return "Checks that a harmless request is answered rather than refused.";
  return "No reliable automatic evaluator exists for custom prompts in this category, so the result will be Needs review unless your objective has machine-checkable rules.";
}

export default function RedTeam() {
  const [cases, setCases] = useState([]);
  const [categories, setCategories] = useState(Object.keys(CATEGORY_LABELS));
  const [model, setModel] = useState(null); // null = checking
  const [caseId, setCaseId] = useState("");
  const [prompt, setPrompt] = useState("");
  const [category, setCategory] = useState("miscellaneous");
  const [objective, setObjective] = useState("");
  const [mode, setMode] = useState("auto");
  const [trials, setTrials] = useState(1);
  const [busy, setBusy] = useState(null); // "run" | "suite" | null
  const [result, setResult] = useState(null);
  const [suite, setSuite] = useState(null);
  const [error, setError] = useState("");
  const [retry, setRetry] = useState(null);
  const [dash, setDash] = useState(null);
  const [recent, setRecent] = useState([]);
  const loadStats = useCallback(() => {
    api.dashboard().then(setDash).catch(() => {});
    api.tests({ limit: 200 }).then((d) => setRecent(d.items)).catch(() => {});
  }, []);

  const checkModel = useCallback(() => {
    setModel(null);
    api.aiHealth().then(setModel).catch((e) => setModel({ ok: false, detail: e.message }));
  }, []);

  useEffect(() => {
    checkModel(); loadStats();
    api.testCases().then((d) => { setCases(d.cases); setCategories(d.categories.map((c) => c.id)); }).catch((e) => setError(e.message));
  }, [checkModel, loadStats]);

  const selected = cases.find((c) => c.id === caseId);
  const shownPrompt = selected ? selected.prompt : prompt;
  const shownCategory = selected ? selected.category : category;

  async function perform(kind) {
    setBusy(kind); setError(""); setResult(null); setSuite(null); setRetry(() => () => perform(kind));
    try {
      if (kind === "suite") setSuite(await api.runSuite(mode, trials));
      else setResult(await api.runTest(selected ? { test_case_id: selected.id, mode, trials } : { prompt: prompt.trim(), category, mode, trials, ...(objective.trim() ? { test_objective: objective.trim() } : {}) }));
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(null);
      checkModel(); loadStats();
    }
  }

  const modelDot = model === null ? "checking" : model.ok ? "online" : "offline";
  const cats = (dash?.by_category || []).map((c) => ({ name: CATEGORY_LABELS[c.category] || c.category, value: c.PASS + c.FAIL + c.NEEDS_REVIEW + (c.NOT_APPLICABLE || 0) + c.ERROR, category: c.category }));
  const attackTypes = cats.filter((c) => isAttack(c.category) && c.value > 0).length;
  const days = lastDays(recent);
  return (
    <div className="team team-red">
      <header className="team-hero">
        <Crosshair size={44} strokeWidth={1.5} color="var(--accent)" />
        <div><h1>Red Team</h1><p>Test the AI with safe, controlled attacks and see in plain English what needs fixing.</p></div>
      </header>
      <section className="team-kpis">
        {[[FileText, dash?.total_tests ?? "—", "Tests run"], [TriangleAlert, dash?.failed ?? "—", "Vulnerabilities found"], [Target, dash ? attackTypes : "—", "Attack types tested"]].map(([I, v, l]) => (
          <div className="team-kpi" key={l}><span className="team-ico"><I size={24} strokeWidth={1.6} /></span><div><b>{v}</b><span>{l}</span></div></div>
        ))}
      </section>
      <nav className="team-tabs" aria-label="Red Team sections"><span className="on">Attack Playground</span><Link to="/history">Test History</Link></nav>

      <section className="model-bar team-bar">
        <div><span className={`dot ${modelDot}`} />
          {model === null ? "Checking model…" : <>{model.ok ? "Model connected" : "Model unavailable"}{model.model ? ` · ${model.provider}/${model.model}` : ""}</>}
        </div>
        {model && !model.ok && <div className="muted">{model.detail}</div>}
        <button className="btn" onClick={checkModel} disabled={busy}>Recheck</button>
      </section>

      <RedGuide cases={cases} model={model} checkModel={checkModel} onDone={loadStats} />

      <details className="advanced team-panel"><summary><b>Advanced: run a single test, repeat trials, or try your own prompt</b></summary>
      <section className="team-grid">
        <div className="team-panel form">
          <h2>Configure Attack</h2>
          <label htmlFor="mode">Defenses</label>
          <select id="mode" value={mode} onChange={(e) => setMode(e.target.value)} disabled={!!busy}>
            <option value="auto">Use the Blue Team defenses if configured</option>
            <option value="baseline">None (baseline)</option>
          </select>
          <label htmlFor="case">Test case</label>
          <select id="case" value={caseId} onChange={(e) => setCaseId(e.target.value)} disabled={!!busy}>
            <option value="">Custom prompt</option>
            {cases.map((c) => <option key={c.id} value={c.id} disabled={c.availability !== "implemented"}>{CATEGORY_LABELS[c.category]}: {c.name}{c.availability !== "implemented" ? " (requires integration)" : ""}</option>)}
          </select>
          {selected && <p className="muted small">{selected.description} · {selected.severity} severity · {selected.owasp.join(", ") || "control"}<br />Success: {selected.success_criteria}<br />Remediation: {selected.remediation}</p>}
          <label htmlFor="trials">Repeated trials</label>
          <select id="trials" value={trials} onChange={(e) => setTrials(Number(e.target.value))} disabled={!!busy}>
            {[1, 3, 5, 10].map((n) => <option value={n} key={n}>{n} {n === 1 ? "trial" : "trials"}</option>)}
          </select>
          <label htmlFor="cat">Category</label>
          <select id="cat" value={shownCategory} onChange={(e) => setCategory(e.target.value)} disabled={!!selected || !!busy}>
            {categories.map((c) => <option key={c} value={c}>{CATEGORY_LABELS[c] || c}</option>)}
          </select>
          <label htmlFor="prompt">Test prompt</label>
          <textarea id="prompt" rows={5} maxLength={2000} value={shownPrompt} readOnly={!!selected} onChange={(e) => setPrompt(e.target.value)} placeholder="Enter a prompt to test…" />
          <div className="muted small" style={{ textAlign: "right" }}>{shownPrompt.length}/2000</div>
          {!selected && (
            <>
              <label htmlFor="objective">Test objective <span className="muted small">(optional)</span></label>
              <textarea id="objective" rows={2} maxLength={500} value={objective} onChange={(e) => setObjective(e.target.value)} disabled={!!busy}
                placeholder={"Expected behavior. Machine-checkable lines: contains: x, y · not_contains: z · max_words: 50"} />
              <p className="muted small">{categoryHelp(category)}</p>
            </>
          )}
          <p className="muted small">Model: {model?.model ? `${model.provider}/${model.model}` : "set by the server (AI_PROVIDER / AI_MODEL)"}. The provider is configured on the backend and cannot be changed per prompt.</p>
          <div className="row">
            <button className="btn accent" disabled={!!busy || (!selected && !prompt.trim())} onClick={() => perform("run")}><Play size={15} /> {busy === "run" ? "Running…" : "Run test"}</button>
            <button className="btn" disabled={!!busy} onClick={() => perform("suite")}><ListChecks size={15} /> {busy === "suite" ? "Running suite…" : "Run full test suite"}</button>
          </div>
          {busy && <p className="muted small" role="status">{busy === "suite" ? "Running all 11 tests one by one. A local model can take several minutes." : "Waiting for the model…"}</p>}
        </div>

        <div className="team-panel">
          <h2>Test Preview</h2>
          {result && <p><StatusPair executionStatus={result.execution_status} verdict={result.security_verdict} severity={result.severity ?? null} /></p>}
          <div className="pv pv-user"><div className="pv-l">USER (ATTACK PROMPT)</div>{shownPrompt || <span className="muted">Pick a test case or type a prompt.</span>}</div>
          <div className="pv pv-model"><div className="pv-l">MODEL RESPONSE</div>
            {result ? (result.response ? <pre>{result.response}</pre> : <span className="muted">No response was received.</span>) : <span className="muted">Run the test to see the model's real response.</span>}
          </div>
          {result && (
            <div className="pv-eval">
              <p><span className="muted">{secs(result.duration_ms)} · {result.provider || "—"}/{result.model || "—"}</span> {result.mode === "defended"
                ? <span className={`tag ${result.defense_triggered ? "" : "ok"}`}>{result.defense_triggered ? "Defense triggered" : "Defenses active, not triggered"}</span>
                : <span className="muted">· No defenses (baseline)</span>}</p>
              {result.error_message && <div className="fd-err" role="alert">Execution error: {result.error_message}</div>}
              <p><b>Reason:</b> {result.explanation}</p>
              <p className="muted small">Category: {CATEGORY_LABELS[result.category] || result.category}{result.test_objective ? ` · Objective: ${result.test_objective}` : ""} · {fmt(result.created_at)}</p>
              <p className="row"><Link className="btn" to={`/history/${result.test_id}`}><ExternalLink size={14} /> View full result</Link>{result.execution_status === "ERROR" && retry && <button className="btn" onClick={retry}>Retry</button>}</p>
            </div>
          )}
        </div>
      </section>

      {error && (
        <div className="state error" role="alert"><p>{error}</p>{retry && <button className="btn" onClick={retry}>Retry</button>}</div>
      )}

      {suite && (
        <section className="team-panel">
          <h2>Suite results</h2>
          <p className="muted">{suite.total} outcomes across {suite.trials} trial(s) · {suite.counts.PASS} pass · {suite.counts.FAIL} fail · {suite.counts.NEEDS_REVIEW} need review · {suite.counts.ERROR} execution error</p>
          {suite.limitations?.map((note) => <p className="muted small" key={note}>{note}</p>)}
          <div className="table-wrap"><table>
            <thead><tr><th>Test</th><th>Category</th><th>Execution</th><th>Security verdict</th><th>Severity</th><th>Defense triggered</th><th>Time</th></tr></thead>
            <tbody>{suite.results.map((r) => (
              <tr key={r.test_id}><td><Link to={`/history/${r.test_id}`}>{r.test_name}</Link></td><td>{CATEGORY_LABELS[r.category]}</td><td><ExecBadge status={r.execution_status} /></td><td><VerdictBadge verdict={r.security_verdict} executionStatus={r.execution_status} /></td><td><SeverityBadge severity={r.severity} /></td><td>{r.mode === "defended" ? (r.defense_triggered ? "Yes" : "No") : "n/a"}</td><td>{secs(r.duration_ms)}</td></tr>
            ))}</tbody>
          </table></div>
        </section>
      )}

      </details>

      <section className="team-panel">
        <div className="card-h"><h2>Recent Red Team Tests</h2><Link to="/history" className="small">View all →</Link></div>
        {recent.length === 0 ? <div className="empty">No tests yet. Run one above.</div> : (
          <div className="table-wrap"><table>
            <thead><tr><th>Test</th><th>Model</th><th>Category</th><th>Mode</th><th>Execution</th><th>Security verdict</th><th>Severity</th><th>Date</th></tr></thead>
            <tbody>{recent.slice(0, 5).map((r) => (
              <tr key={r.test_id}><td><Link to={`/history/${r.test_id}`}>{r.test_name || r.test_id}</Link></td><td>{r.model || "—"}</td><td>{CATEGORY_LABELS[r.category] || r.category}</td><td style={{ textTransform: "capitalize" }}>{r.mode}</td><td><ExecBadge status={r.execution_status} /></td><td><VerdictBadge verdict={r.security_verdict} executionStatus={r.execution_status} /></td><td><SeverityBadge severity={r.severity} /></td><td>{new Date(r.created_at).toLocaleDateString()}</td></tr>
            ))}</tbody>
          </table></div>)}
      </section>

      <section className="team-grid">
        <div className="team-panel"><h2>Category Distribution</h2><Donut parts={cats} colors={REDS} /></div>
        <div className="team-panel"><h2>Outcome Trend <span className="muted small">last 7 days</span></h2>
          <TrendChart data={days} aKey="Detected" bKey="Blocked" aColor="#ef4444" bColor="#fca5a5" aLabel="Detected (attack succeeded)" bLabel="Blocked" /></div>
      </section>
    </div>
  );
}
