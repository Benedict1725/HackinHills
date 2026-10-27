import { useCallback, useEffect, useRef, useState } from "react";
import { RefreshCw, RotateCcw } from "lucide-react";
import { api } from "../services/api";
import { CATEGORY_LABELS, ErrorState, EXEC_OPTIONS, ExecBadge, Loading, SEVERITY_OPTIONS, SeverityBadge, StatusPair, VERDICT_OPTIONS, VerdictBadge, fmt, secs } from "./ui";

const POLL_MS = 10000;
const EFFECT = {
  blocked: ["Blocked by input screen", "passed"], mitigated: ["Mitigated", "passed"], not_mitigated: ["Not mitigated", "failed"],
  worse: ["Worse with defenses", "failed"], not_applicable: ["Nothing to mitigate", "err"], inconclusive: ["Inconclusive", "review"],
  no_verdict: ["No security verdict to compare", "na"],
  false_refusal: ["False refusal", "failed"], error: ["Retest failed", "err"],
};
const VULN = { detected: "Vulnerable", not_detected: "Not vulnerable", inconclusive: "Inconclusive", not_applicable: "Not applicable", unknown: "Not evaluated" };
const yn = (v) => (v === true ? "Vulnerable" : v === false ? "Not vulnerable" : "No confirmed verdict");
const preview = (s, n = 80) => (s.length > n ? `${s.slice(0, n)}…` : s);

function Side({ title, mode, response, error, execution, verdict, explanation, vuln, severity, extra }) {
  return (
    <div className="team-panel">
      <h3>{title}</h3>
      <p className="small"><StatusPair executionStatus={execution} verdict={verdict} severity={severity ?? null} /></p>
      <p className="small muted">{mode}</p>
      {error && <div className="fd-err" role="alert">Execution error: {error}</div>}
      <div className="pv pv-model"><div className="pv-l">RESPONSE</div>{response ? <pre>{response}</pre> : <span className="muted">No response was received.</span>}</div>
      <p className="small"><b>Vulnerability:</b> {vuln}</p>
      {explanation && <p className="small muted"><b>Reason:</b> {explanation}</p>}
      {extra}
    </div>
  );
}

function Comparison({ rt }) {
  const a = rt.assessment, o = rt.original;
  const [label, cls] = EFFECT[a.effect] || [a.effect, "review"];
  return (
    <div>
      <p><span className={`badge ${cls}`}>{label}</span> <span className="muted small">retested {fmt(rt.retested_at)} · {secs(rt.duration_ms)} · retest {rt.retest_id}</span></p>
      <p>{a.summary}</p>
      {a.responses_identical !== null && a.responses_identical !== undefined && <p className="small"><b>Responses:</b> {a.responses_identical ? "identical" : "different"}</p>}
      {a.notes.map((n) => <p className="muted small" key={n}>{n}</p>)}
      <div className="fd-cmp">
        <Side title="Original (Red Team)" mode={`${o.original_mode === "defended" ? "Defenses on" : "No defenses"} · ${o.provider}/${o.model}`} response={o.response} error={o.error}
          execution={o.execution_status} verdict={o.security_verdict} explanation={o.explanation} vuln={yn(a.vulnerable_before)} severity={a.severity_before} />
        <Side title="With saved defenses" mode={`Config v${rt.defense_config_id ?? "—"}`} response={rt.response} error={rt.error} execution={rt.execution_status} verdict={rt.security_verdict}
          explanation={rt.explanation} vuln={yn(a.vulnerable_after)} severity={a.severity_after}
          extra={<p className="small muted">Defense actions: {rt.defense_actions.length ? rt.defense_actions.join(", ") : "none applied"}</p>} />
      </div>
    </div>
  );
}

export default function RedTeamFindings({ canRetest, hasConfig }) {
  const [items, setItems] = useState(null);
  const [total, setTotal] = useState(0);
  const [error, setError] = useState("");          // initial/manual load failure (blocks the list)
  const [pollError, setPollError] = useState("");  // background refresh failure (keeps the list)
  const [refreshing, setRefreshing] = useState(false);
  const [fresh, setFresh] = useState(new Set());
  const [updated, setUpdated] = useState(null);
  const [selected, setSelected] = useState(null);
  const [detail, setDetail] = useState(null);       // { finding, retests }
  const [detailError, setDetailError] = useState("");
  const [retesting, setRetesting] = useState(false);
  const [retestError, setRetestError] = useState("");
  const [shown, setShown] = useState(null);         // which retest is displayed
  const seen = useRef(null);
  const [filters, setFilters] = useState({ severity: "", verdict: "", category: "", execution_status: "" });
  const filtersRef = useRef(filters);
  filtersRef.current = filters;

  const load = useCallback(async ({ silent = false } = {}) => {
    if (!silent) { setRefreshing(true); setError(""); }
    try {
      const d = await api.findings({ limit: 50, ...filtersRef.current });
      const ids = new Set(d.items.map((f) => f.test_id));
      if (seen.current) {
        const added = d.items.filter((f) => !seen.current.has(f.test_id)).map((f) => f.test_id);
        if (added.length) setFresh((prev) => new Set([...prev, ...added]));
      }
      seen.current = new Set([...(seen.current || []), ...ids]);
      setItems(d.items); setTotal(d.total); setUpdated(new Date()); setPollError("");
    } catch (e) {
      if (silent && seen.current) setPollError(e.message); else setError(e.message);
    } finally { if (!silent) setRefreshing(false); }
  }, []);

  useEffect(() => { seen.current = null; setFresh(new Set()); load(); }, [load, filters]);  // a filter change is not "new findings"
  useEffect(() => {
    const tick = () => { if (!document.hidden) load({ silent: true }); };
    const t = setInterval(tick, POLL_MS);
    document.addEventListener("visibilitychange", tick);
    return () => { clearInterval(t); document.removeEventListener("visibilitychange", tick); };
  }, [load]);

  const loadDetail = useCallback(async (id) => {
    setDetailError("");
    try {
      const d = await api.finding(id);
      setDetail(d); setShown(d.retests[0]?.retest_id ?? null);
    } catch (e) { setDetail(null); setDetailError(e.message); }
  }, []);
  function select(id) {
    setSelected(id); setDetail(null); setRetestError(""); setShown(null);
    setFresh((p) => { const n = new Set(p); n.delete(id); return n; });
    loadDetail(id);
  }
  async function retest() {
    setRetesting(true); setRetestError("");
    try {
      const rt = await api.retestFinding(selected);
      setDetail((d) => d && { finding: { ...d.finding, retest_count: d.finding.retest_count + 1 }, retests: [rt, ...d.retests] });
      setShown(rt.retest_id);
      load({ silent: true });
    } catch (e) { setRetestError(e.message); } finally { setRetesting(false); }
  }

  if (error && !items) return <section className="team-panel"><h2>Red Team Findings</h2><ErrorState message={error} onRetry={() => load()} /></section>;
  if (!items) return <Loading label="Loading Red Team findings…" />;
  const f = detail?.finding;
  const rt = detail?.retests.find((r) => r.retest_id === shown);
  return (
    <>
      <section className="team-panel">
        <div className="card-h"><h2>Red Team Findings</h2><span className="muted small">{total} total</span></div>
        <div className="fd-bar">
          {fresh.size > 0 && <span className="fd-new" role="status">{fresh.size} new {fresh.size === 1 ? "finding" : "findings"} arrived</span>}
          {pollError && <span className="muted small" role="alert">Auto-refresh failed: {pollError}</span>}
          {updated && <span className="muted small">Updated {updated.toLocaleTimeString()} · auto-refreshes every {POLL_MS / 1000}s</span>}
          <button className="btn" onClick={() => load()} disabled={refreshing}><RefreshCw size={14} /> {refreshing ? "Refreshing…" : "Refresh"}</button>
        </div>
        <div className="fd-filters" role="group" aria-label="Filter findings">
          {[["severity", "Severity", SEVERITY_OPTIONS], ["verdict", "Security verdict", VERDICT_OPTIONS], ["execution_status", "Execution status", EXEC_OPTIONS]].map(([k, label, opts]) => (
            <select key={k} aria-label={`Filter by ${label.toLowerCase()}`} value={filters[k]} onChange={(e) => setFilters({ ...filters, [k]: e.target.value })}>
              <option value="">All {label.toLowerCase()}s</option>{opts.map((o) => <option key={o} value={o}>{o.replace("_", " ")}</option>)}
            </select>))}
          <select aria-label="Filter by attack category" value={filters.category} onChange={(e) => setFilters({ ...filters, category: e.target.value })}>
            <option value="">All attack categories</option>{Object.entries(CATEGORY_LABELS).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
          </select>
          {Object.values(filters).some(Boolean) && <button className="btn" onClick={() => setFilters({ severity: "", verdict: "", category: "", execution_status: "" })}>Clear filters</button>}
        </div>
        {error && <ErrorState message={error} onRetry={() => load()} />}
        {items.length === 0 ? (
          <div className="empty">{Object.values(filters).some(Boolean) ? "No findings match these filters." : "No Red Team tests have been submitted yet. When a Red Team user runs a prompt it will appear here automatically."}</div>
        ) : (
          <div className="table-wrap"><table>
            <thead><tr><th>Submitted</th><th>Finding ID</th><th>Prompt</th><th>Model</th><th>Category</th><th>Execution</th><th>Security verdict</th><th>Severity</th><th>Retests</th></tr></thead>
            <tbody>{items.map((x) => (
              <tr key={x.test_id} className={`fd-row${selected === x.test_id ? " sel" : ""}${fresh.has(x.test_id) ? " fresh" : ""}`} onClick={() => select(x.test_id)}>
                <td>{fmt(x.created_at)}</td>
                <td><button className="linklike" onClick={(e) => { e.stopPropagation(); select(x.test_id); }}>{x.test_id}</button></td>
                <td className="fd-prompt" title={x.prompt}>{preview(x.prompt)}</td>
                <td>{x.model ? `${x.provider}/${x.model}` : "—"}</td>
                <td>{CATEGORY_LABELS[x.category] || x.category}</td>
                <td><ExecBadge status={x.execution_status} /></td>
                <td><VerdictBadge verdict={x.security_verdict} executionStatus={x.execution_status} /> {x.execution_status !== "ERROR" && <span className="muted small">{VULN[x.vulnerability]}</span>}</td>
                <td><SeverityBadge severity={x.severity} /></td>
                <td>{x.retest_count}</td>
              </tr>))}</tbody>
          </table></div>
        )}
        {total > items.length && <p className="muted small">Showing the newest {items.length} of {total}.</p>}
      </section>

      {selected && (
        <section className="team-panel fd-detail" aria-live="polite">
          <h2>Finding {selected}</h2>
          {detailError && <ErrorState message={detailError} onRetry={() => loadDetail(selected)} />}
          {!detail && !detailError && <Loading label="Loading finding…" />}
          {f && (
            <>
              <p className="small muted">{CATEGORY_LABELS[f.category] || f.category} · {f.test_name || "Custom prompt"} · {f.provider}/{f.model || "—"} · submitted {fmt(f.created_at)} · Red Team ran it {f.original_mode === "defended" ? "with defenses on" : "without defenses"}</p>
              <div className="pv pv-user"><div className="pv-l">RED TEAM PROMPT (exactly as saved; this is what Retest sends)</div><pre>{f.prompt}</pre></div>
              {f.test_objective && <p className="small"><b>Test objective:</b> {f.test_objective}</p>}
              <p><StatusPair executionStatus={f.execution_status} verdict={f.security_verdict} severity={f.severity ?? null} /></p>
              <details open>
                <summary>Model response and evaluation</summary>
                {f.error && <div className="fd-err" role="alert">Execution error: {f.error}</div>}
                <div className="pv pv-model"><div className="pv-l">MODEL RESPONSE</div>{f.response ? <pre>{f.response}</pre> : <span className="muted">No response was received.</span>}</div>
                {f.explanation && <p className="small muted"><b>Reason:</b> {f.explanation}</p>}
              </details>
              {canRetest && (
                <div className="row" style={{ margin: ".8rem 0" }}>
                  <button className="btn accent" disabled={retesting || !hasConfig} onClick={retest}><RotateCcw size={15} /> {retesting ? "Retesting…" : "Retest with defenses"}</button>
                  {!hasConfig && <span className="muted small">Save a defense configuration first (Defense Playground tab).</span>}
                </div>
              )}
              {!canRetest && <p className="muted small">Read-only: only Blue Team users can retest.</p>}
              {retesting && <p className="muted small" role="status">Re-running the saved prompt against the real model with your active defenses…</p>}
              {retestError && <ErrorState message={retestError} onRetry={retest} />}
              {detail.retests.length > 1 && (
                <p className="small">Retests: {detail.retests.map((r, i) => (
                  <button key={r.retest_id} className="linklike" style={{ marginRight: ".6rem", fontWeight: r.retest_id === shown ? 700 : 400 }} onClick={() => setShown(r.retest_id)}>#{detail.retests.length - i} {fmt(r.retested_at)}</button>))}</p>
              )}
              {rt ? <Comparison rt={rt} /> : <p className="muted small">No retest yet for this finding.</p>}
            </>
          )}
        </section>
      )}
    </>
  );
}
