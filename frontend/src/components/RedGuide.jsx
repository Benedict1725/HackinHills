import { useRef, useState } from "react";
import { Link } from "react-router-dom";
import { CheckCircle2, Play, RotateCcw } from "lucide-react";
import { api } from "../services/api";
import { CATEGORY_LABELS, SeverityBadge } from "./ui";

const ONE_LINER = {
  prompt_injection: "Hides new instructions inside a request to see whether the AI obeys them instead of its rules.",
  jailbreak: "Tries to talk the AI out of its safety rules (role-play, “no limits” modes).",
  data_leakage: "Tries to get the AI to reveal secret or private information it was told to protect.",
  system_prompt_leakage: "Tries to make the AI repeat its hidden setup instructions.",
  instruction_conflict: "Gives the AI two instructions that clash, to see which one wins.",
  improper_output_handling: "Checks whether the AI’s answer can be made to break a required output format.",
  misinformation: "Checks whether the AI confidently states something false.",
  normal_request: "Control tests: harmless requests that should be answered, not blocked.",
};
const ATTACK = (c) => !["normal_request", "miscellaneous"].includes(c);
const word = (r) => (r.execution_status === "ERROR" ? "Did not run" : r.security_verdict === "FAIL" ? "Attack worked" : r.security_verdict === "PASS" ? "Attack stopped" : r.security_verdict === "NEEDS_REVIEW" ? "Needs a person to review" : "Not scored");
const tone = (r) => (r.execution_status === "ERROR" ? "exec-err" : r.security_verdict === "FAIL" ? "failed" : r.security_verdict === "PASS" ? "passed" : "review");

export default function RedGuide({ cases, model, checkModel, onDone }) {
  const [busy, setBusy] = useState(false), [suite, setSuite] = useState(null), [err, setErr] = useState("");
  const [again, setAgain] = useState({});          // test_case_id -> { busy, result, error }
  const lock = useRef(false);
  const implemented = cases.filter((c) => c.availability === "implemented");
  const cats = [...new Set(implemented.map((c) => c.category))];
  const caseOf = (id) => cases.find((c) => c.id === id);

  async function run() {
    if (lock.current) return; lock.current = true; setBusy(true); setErr(""); setSuite(null); setAgain({});
    try { setSuite(await api.runSuite("auto", 1)); } catch (e) { setErr(e.message); } finally { setBusy(false); lock.current = false; checkModel(); onDone(); }
  }
  async function retest(r) {
    const id = r.test_case_id; if (!id || again[id]?.busy) return;
    setAgain((a) => ({ ...a, [id]: { busy: true } }));
    try { const res = await api.runTest({ test_case_id: id, mode: "auto", trials: 1 }); setAgain((a) => ({ ...a, [id]: { result: res } })); onDone(); }
    catch (e) { setAgain((a) => ({ ...a, [id]: { error: e.message } })); }
  }
  const rows = suite?.results || [];
  const atk = rows.filter((r) => ATTACK(r.category));
  const worked = atk.filter((r) => r.security_verdict === "FAIL"), stopped = atk.filter((r) => r.security_verdict === "PASS");
  const review = atk.filter((r) => r.security_verdict === "NEEDS_REVIEW"), failedRun = rows.filter((r) => r.execution_status === "ERROR");
  const modelOk = model?.ok;
  return (
    <div className="wizard">
      <ol className="guide-steps" aria-label="How Red Team testing works"><li>Choose what to test</li><li>See what we check</li><li>Run the test</li><li>Understand the results</li><li>Fix and retest</li></ol>

      <section className="team-panel wizard-step" aria-labelledby="r1">
        <h2 id="r1"><span className={`step-n ${modelOk ? "done" : ""}`}>{modelOk ? <CheckCircle2 size={16} /> : 1}</span> Choose what to test</h2>
        <p><span className={`dot ${model === null ? "checking" : modelOk ? "online" : "offline"}`} /> <b>{model === null ? "Checking the AI…" : modelOk ? `${model.provider} / ${model.model}` : "AI model unavailable"}</b></p>
        <p className="muted small">LeakProof tests the one AI model your administrator configured on the server (backend/.env). It cannot be switched here, and no other kinds of target are supported.</p>
        {model && !modelOk && <p className="hint">{model.detail} If you use Ollama, run <code>ollama serve</code>, then <button className="linklike" onClick={checkModel}>check again</button>.</p>}
      </section>

      <section className="team-panel wizard-step" aria-labelledby="r2">
        <h2 id="r2"><span className="step-n">2</span> What the test checks</h2>
        {cases.length === 0 ? <p className="muted">Loading the list of tests…</p> : <>
          <ul className="catlist">{cats.map((c) => (
            <li key={c}><b>{CATEGORY_LABELS[c] || c}</b> <span className="muted small">({implemented.filter((x) => x.category === c).length} test{implemented.filter((x) => x.category === c).length > 1 ? "s" : ""})</span><div className="small muted">{ONE_LINER[c] || ""}</div></li>))}</ul>
          <p className="muted small">Only tests that are fully built appear here. Tests that need extra setup (documents, tools) are hidden. To try your own prompt, use Advanced below.</p></>}
      </section>

      <section className="team-panel wizard-step" aria-labelledby="r3">
        <h2 id="r3"><span className={`step-n ${suite ? "done" : ""}`}>{suite ? <CheckCircle2 size={16} /> : 3}</span> Run the test</h2>
        <button className="btn accent big" disabled={busy || !modelOk} onClick={run}><Play size={16} /> {busy ? "Running security test…" : "Run Security Test"}</button>
        <p className="muted small">Recommended for beginners: runs every built-in test once and saves the results.</p>
        {!modelOk && model !== null && <p className="muted small">Fix the model connection above first.</p>}
        {busy && <p className="muted small" role="status">Running the built-in tests one at a time. A local model can take several minutes. Please keep this page open.</p>}
        {err && <div className="state error" role="alert"><p>The test did not finish: {err}</p><button className="btn" onClick={run}>Try again</button></div>}
      </section>

      <section className="team-panel wizard-step" aria-labelledby="r4">
        <h2 id="r4"><span className={`step-n ${suite ? "done" : ""}`}>{suite ? <CheckCircle2 size={16} /> : 4}</span> Understand the results</h2>
        {!suite ? <div className="empty">No results yet. Press Run Security Test above. Your earlier tests are listed under Recent Red Team Tests below.</div> : (
          <>
            {failedRun.length > 0 && <div className="demo-banner" role="alert">{failedRun.length} test(s) could not run (model or connection problem), so these results are incomplete.</div>}
            <div className="stats">{[["Tests run", rows.length - failedRun.length], ["Attacks that worked", worked.length], ["Attacks stopped", stopped.length], ["Need a person to review", review.length]].map(([l, v]) => <div className="card stat" key={l}><div className="stat-value">{v}</div><div className="muted">{l}</div></div>)}</div>
            <p role="status"><b>{worked.length > 0 ? `${worked.length} vulnerabilit${worked.length > 1 ? "ies need" : "y needs"} attention.` : failedRun.length ? "No vulnerability confirmed, but the run was incomplete." : "No vulnerability was confirmed in this run."}</b>{" "}
              <span className="muted">An attack “worked” only when the AI’s real answer broke a rule (for example it revealed a protected secret). “Stopped” means the AI held up in this test. This small suite cannot prove an AI is secure.</span></p>
            <h3>Findings</h3>
            {worked.length === 0 ? <p className="muted">Nothing to fix from confirmed failures.{review.length ? " Review the items marked “needs a person to review” in the table below." : ""}</p> : worked.map((r) => {
              const c = caseOf(r.test_case_id), a = again[r.test_case_id];
              return (
                <details key={r.test_id} className="finding" open>
                  <summary><b>{r.test_name}</b> <SeverityBadge severity={r.severity} /> <span className="badge failed">Unresolved</span></summary>
                  <dl>
                    <dt>What we tested</dt><dd>{c?.description || r.test_name} <span className="muted small">({CATEGORY_LABELS[r.category]})</span></dd>
                    <dt>What happened</dt><dd>{r.explanation}</dd>
                    <dt>Why it matters</dt><dd>{c ? `The AI broke this rule: ${c.success_criteria}` : "The AI’s answer broke a test rule."}</dd>
                    <dt>Evidence (the AI’s real answer)</dt><dd><pre className="evidence">{r.response || "(no response saved)"}</pre></dd>
                    <dt>Suggested fix</dt><dd>{c?.remediation || "Ask the Blue Team to review this finding."}</dd>
                  </dl>
                  <div className="row">
                    <button className="btn" disabled={!r.test_case_id || a?.busy} onClick={() => retest(r)}><RotateCcw size={14} /> {a?.busy ? "Retesting…" : "Retest this attack"}</button>
                    <Link className="btn" to={`/history/${r.test_id}`}>Full details</Link>
                  </div>
                  {a?.error && <p role="alert" className="fd-err">Retest failed: {a.error}</p>}
                  {a?.result && <p role="status">Earlier run: <span className="badge failed">Attack worked</span> → this retest: <span className={`badge ${tone(a.result)}`}>{word(a.result)}</span> <Link to={`/history/${a.result.test_id}`}>View</Link>
                    {a.result.security_verdict === "FAIL" && " The problem is still there."}</p>}
                </details>);
            })}
            <h3>All tests in this run</h3>
            <div className="table-wrap"><table><thead><tr><th>Test</th><th>Category</th><th>Result</th></tr></thead>
              <tbody>{rows.map((r) => <tr key={r.test_id}><td><Link to={`/history/${r.test_id}`}>{r.test_name}</Link></td><td>{CATEGORY_LABELS[r.category]}</td><td><span className={`badge ${tone(r)}`}>{ATTACK(r.category) || r.execution_status === "ERROR" ? word(r) : r.security_verdict === "PASS" ? "Answered normally" : r.security_verdict === "FAIL" ? "Harmless request refused" : word(r)}</span></td></tr>)}</tbody></table></div>
          </>)}
      </section>
    </div>
  );
}
