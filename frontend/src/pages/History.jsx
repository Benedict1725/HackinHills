import { useCallback, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../services/api";
import { useApi } from "../services/useApi";
import { Badge, CATEGORY_LABELS, ErrorState, Loading, PageHeader, STATUS_OPTIONS, fmt } from "../components/ui";

export default function History() {
  const [category, setCategory] = useState("");
  const [status, setStatus] = useState("");
  const fetcher = useCallback(() => api.tests({ category, status, limit: 200 }), [category, status]);
  const { data, error, loading, retry } = useApi(fetcher);
  return (
    <>
      <PageHeader title="Test History" subtitle="Every saved test result, newest first." />
      <div className="filters">
        <select aria-label="Filter by category" value={category} onChange={(e) => setCategory(e.target.value)}>
          <option value="">All categories</option>
          {Object.entries(CATEGORY_LABELS).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
        </select>
        <select aria-label="Filter by status" value={status} onChange={(e) => setStatus(e.target.value)}>
          <option value="">All statuses</option>
          {STATUS_OPTIONS.map((s) => <option key={s} value={s}>{s.replace("_", " ")}</option>)}
        </select>
      </div>
      {error ? <ErrorState message={error} onRetry={retry} /> : loading && !data ? <Loading label="Loading test history…" /> : (
        <section className="card table-wrap">
          <table>
            <thead><tr><th>Test ID</th><th>Category</th><th>Model</th><th>Outcome</th><th>Defense</th><th>Timestamp</th></tr></thead>
            <tbody>
              {data.items.length === 0 ? (
                <tr><td colSpan={6} className="muted">{category || status ? "No results match these filters." : "No saved results yet. Run a test in the Red Team Console."}</td></tr>
              ) : data.items.map((t) => (
                <tr key={t.test_id}>
                  <td><Link to={`/history/${t.test_id}`}>{t.test_id}</Link></td>
                  <td>{CATEGORY_LABELS[t.category] || t.category}</td>
                  <td>{t.model ? `${t.provider}/${t.model}` : "—"}</td>
                  <td><Badge kind={t.outcome} />{t.false_refusal && <span className="tag">false refusal</span>}</td><td>{t.mode === "defended" ? (t.defense_triggered ? "Triggered" : "Active") : "Off"}</td><td>{fmt(t.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}
    </>
  );
}
