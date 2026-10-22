import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../services/api";
import { Badge, CATEGORY_LABELS, PageHeader, secs } from "../components/ui";

export default function RedTeam() {
  const [cases, setCases] = useState([]);
  const [categories, setCategories] = useState(Object.keys(CATEGORY_LABELS));
  const [model, setModel] = useState(null); // null = checking
  const [caseId, setCaseId] = useState("");
  const [prompt, setPrompt] = useState("");
  const [category, setCategory] = useState("prompt_injection");
  const [mode, setMode] = useState("auto");
  const [busy, setBusy] = useState(null); // "run" | "suite" | null
  const [result, setResult] = useState(null);
  const [suite, setSuite] = useState(null);
  const [error, setError] = useState("");
  const [retry, setRetry] = useState(null);

  const checkModel = useCallback(() => {
    setModel(null);
    api.aiHealth().then(setModel).catch((e) => setModel({ ok: false, detail: e.message }));
  }, []);

  useEffect(() => {
    checkModel();
    api.testCases().then((d) => { setCases(d.cases); setCategories(d.categories.map((c) => c.id)); }).catch((e) => setError(e.message));
  }, [checkModel]);

  const selected = cases.find((c) => c.id === caseId);
  const shownPrompt = selected ? selected.prompt : prompt;
  const shownCategory = selected ? selected.category : category;

  async function perform(kind) {
    setBusy(kind); setError(""); setResult(null); setSuite(null); setRetry(() => () => perform(kind));
    try {
      if (kind === "suite") setSuite(await api.runSuite(mode));
      else setResult(await api.runTest(selected ? { test_case_id: selected.id, mode } : { prompt: prompt.trim(), category, mode }));
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(null);
      checkModel();
    }
  }

  const modelDot = model === null ? "checking" : model.ok ? "online" : "offline";
  return (
    <>
      <PageHeader title="Red Team Console" subtitle="Run controlled safety tests against the configured AI model and see how each response is evaluated." />
      <section className="card model-bar">
        <div><span className={`dot ${modelDot}`} />
          {model === null ? "Checking model…" : <>{model.ok ? "Model connected" : "Model unavailable"}{model.model ? ` · ${model.provider}/${model.model}` : ""}</>}
        </div>
        {model && !model.ok && <div className="muted">{model.detail}</div>}
        <button className="btn" onClick={checkModel} disabled={busy}>Recheck</button>
      </section>

      <section className="card form">
        <label htmlFor="mode">Defenses</label>
        <select id="mode" value={mode} onChange={(e) => setMode(e.target.value)} disabled={!!busy}>
          <option value="auto">Use the Blue Team defenses if configured</option>
          <option value="baseline">None (baseline)</option>
        </select>
        <label htmlFor="case">Test case</label>
        <select id="case" value={caseId} onChange={(e) => setCaseId(e.target.value)} disabled={!!busy}>
          <option value="">Custom prompt</option>
          {cases.map((c) => <option key={c.id} value={c.id}>{CATEGORY_LABELS[c.category]}: {c.name}</option>)}
        </select>
        {selected && <p className="muted">{selected.description}</p>}
        <label htmlFor="cat">Test category</label>
        <select id="cat" value={shownCategory} onChange={(e) => setCategory(e.target.value)} disabled={!!selected || !!busy}>
          {categories.map((c) => <option key={c} value={c}>{CATEGORY_LABELS[c] || c}</option>)}
        </select>
        <label htmlFor="prompt">Test prompt</label>
        <textarea id="prompt" rows={5} maxLength={2000} value={shownPrompt} readOnly={!!selected} onChange={(e) => setPrompt(e.target.value)} placeholder="Enter a prompt to test…" />
        {!selected && <p className="muted">Custom prompts run against a fixed system policy holding a synthetic secret. They can be marked Fail if it leaks, otherwise they need human review.</p>}
        <div className="row">
          <button className="btn primary" disabled={!!busy || (!selected && !prompt.trim())} onClick={() => perform("run")}>{busy === "run" ? "Running…" : "Run test"}</button>
          <button className="btn" disabled={!!busy} onClick={() => perform("suite")}>{busy === "suite" ? "Running suite…" : "Run full test suite"}</button>
        </div>
        {busy && <p className="muted" role="status">{busy === "suite" ? "Running all 11 tests one by one. A local model can take several minutes." : "Waiting for the model…"}</p>}
      </section>

      {error && (
        <div className="state error" role="alert"><p>{error}</p>{retry && <button className="btn" onClick={retry}>Retry</button>}</div>
      )}

      {result && (
        <section className="grid2">
          <div className="card"><h2>Model response</h2>{result.response ? <pre>{result.response}</pre> : <p className="muted">No response was received.</p>}</div>
          <div className="card">
            <h2>Evaluation</h2>
            <p><Badge kind={result.outcome} /> <span className="muted">{secs(result.duration_ms)} · {result.provider}/{result.model}</span></p>
            <p>{result.mode === "defended"
              ? <><span className={`tag ${result.defense_triggered ? "" : "ok"}`} style={{ marginLeft: 0 }}>{result.defense_triggered ? "Defense triggered" : "Defenses active, not triggered"}</span></>
              : <span className="muted">No defenses applied (baseline).</span>}</p>
            <p>{result.explanation}</p>
            <p><Link to={`/history/${result.test_id}`}>{result.test_id}</Link> <span className="muted">saved</span></p>
            {result.outcome === "ERROR" && retry && <button className="btn" onClick={retry}>Retry</button>}
          </div>
        </section>
      )}

      {suite && (
        <section className="card">
          <h2>Suite results</h2>
          <p className="muted">{suite.total} tests · {suite.counts.PASS} pass · {suite.counts.FAIL} fail · {suite.counts.NEEDS_REVIEW} need review · {suite.counts.ERROR} error</p>
          <div className="table-wrap"><table>
            <thead><tr><th>Test</th><th>Category</th><th>Outcome</th><th>Defense triggered</th><th>Time</th></tr></thead>
            <tbody>{suite.results.map((r) => (
              <tr key={r.test_id}><td><Link to={`/history/${r.test_id}`}>{r.test_name}</Link></td><td>{CATEGORY_LABELS[r.category]}</td><td><Badge kind={r.outcome} /></td><td>{r.mode === "defended" ? (r.defense_triggered ? "Yes" : "No") : "n/a"}</td><td>{secs(r.duration_ms)}</td></tr>
            ))}</tbody>
          </table></div>
        </section>
      )}
    </>
  );
}
