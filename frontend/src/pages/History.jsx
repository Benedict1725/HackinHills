import { useCallback, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../services/api";
import { useApi } from "../services/useApi";
import { CATEGORY_LABELS, ErrorState, ExecBadge, Loading, PageHeader, SEVERITY_OPTIONS, STATUS_OPTIONS, SeverityBadge, VerdictBadge, fmt } from "../components/ui";

export default function History() {
  const [category, setCategory] = useState("");
  const [status, setStatus] = useState("");
  const [severity, setSeverity] = useState("");
  const fetcher = useCallback(() => api.tests({ category, status, severity, limit: 200 }), [category, status, severity]);
  const { data, error, loading, retry } = useApi(fetcher);
  return (
    <>
      <PageHeader title="Test History" subtitle="Every saved test result, newest first." />
      <div className="filters">
        <select aria-label="Filter by category" value={category} onChange={(e) => setCategory(e.target.value)}>
          <option value="">All categories</option>
          {Object.entries(CATEGORY_LABELS).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
        </select>
        <select aria-label="Filter by result" value={status} onChange={(e) => setStatus(e.target.value)}>
          <option value="">All results</option>
          {STATUS_OPTIONS.map((s) => <option key={s} value={s}>{s.replace("_", " ")}</option>)}
        </select>
        <select aria-label="Filter by severity" value={severity} onChange={(e) => setSeverity(e.target.value)}>
          <option value="">All severities</option>
          {SEVERITY_OPTIONS.map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
      </div>
      {error ? <ErrorState message={error} onRetry={retry} /> : loading && !data ? <Loading label="Loading test history…" /> : (
        <section className="card table-wrap">
          <table>
            <thead><tr><th>Test ID</th><th>Category</th><th>Model</th><th>Execution</th><th>Security verdict</th><th>Severity</th><th>Defense</th><th>Timestamp</th></tr></thead>
            <tbody>
              {data.items.length === 0 ? (
                <tr><td colSpan={8} className="muted">{category || status || severity ? "No results match these filters." : "No saved results yet. Run a test in the Red Team Console."}</td></tr>
              ) : data.items.map((t) => (
                <tr key={t.test_id}>
                  <td><Link to={`/history/${t.test_id}`}>{t.test_id}</Link></td>
                  <td>{CATEGORY_LABELS[t.category] || t.category}</td>
                  <td>{t.model ? `${t.provider}/${t.model}` : "—"}</td>
                  <td><ExecBadge status={t.execution_status} /></td><td><VerdictBadge verdict={t.security_verdict} executionStatus={t.execution_status} />{t.false_refusal && <span className="tag">false refusal</span>}</td><td><SeverityBadge severity={t.severity} /></td><td>{t.mode === "defended" ? (t.defense_triggered ? "Triggered" : "Active") : "Off"}</td><td>{fmt(t.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}
    </>
  );
}
