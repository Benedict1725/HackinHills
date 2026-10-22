import { useCallback, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../services/api";
import { useApi } from "../services/useApi";
import { Badge, ErrorState, Loading, PageHeader, fmt } from "../components/ui";

const FILTERS = [["", "All events"], ["authz", "Authorization failures"], ["auth", "Sign-in events"], ["test", "Test executions"], ["defense", "Defense changes"], ["audit", "Verifications"]];

export default function Audit() {
  const [filter, setFilter] = useState("");
  const [verifying, setVerifying] = useState(false);
  const [verdict, setVerdict] = useState(null);
  const [vError, setVError] = useState("");
  const fetcher = useCallback(() => api.audit({ action: filter, limit: 200 }), [filter]);
  const { data, error, loading, retry } = useApi(fetcher);

  async function verify() {
    setVerifying(true); setVError(""); setVerdict(null);
    try { setVerdict(await api.verifyAudit()); retry(); } catch (e) { setVError(e.message); } finally { setVerifying(false); }
  }
  const ok = verdict?.result === "VERIFIED";
  return (
    <>
      <PageHeader title="Audit Logs" subtitle="Hash-chained security and activity events. Read-only." />
      <div className="row" style={{ marginBottom: "1rem" }}>
        <button className="btn primary" onClick={verify} disabled={verifying}>{verifying ? "Verifying…" : "Verify integrity"}</button>
        <select aria-label="Filter events" value={filter} onChange={(e) => setFilter(e.target.value)} style={{ width: "auto" }}>
          {FILTERS.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
        </select>
      </div>
      {vError && <div className="state error" role="alert"><p>{vError}</p></div>}
      {verdict && (
        <div className={`verdict ${ok ? "ok" : "bad"}`} role="status">
          {verdict.result}
          <p>{verdict.events_checked} events checked.{verdict.head_hash && <> Head hash: <code>{verdict.head_hash}</code></>}</p>
          {verdict.first_inconsistency && (
            <p>First inconsistency: event #{verdict.first_inconsistency.event_id} ({verdict.first_inconsistency.kind.replace("_", " ")}). {verdict.first_inconsistency.detail}</p>
          )}
          <p className="muted">{verdict.note}</p>
        </div>
      )}
      {error ? <ErrorState message={error} onRetry={retry} /> : loading && !data ? <Loading label="Loading audit events…" /> : (
        <section className="card table-wrap">
          <table>
            <thead><tr><th>Event ID</th><th>Action</th><th>Actor</th><th>Test</th><th>Timestamp</th><th>Status</th><th>Hash</th></tr></thead>
            <tbody>
              {data.items.length === 0 ? <tr><td colSpan={7} className="muted">No audit events match.</td></tr> : data.items.map((e) => (
                <tr key={e.id}>
                  <td>{e.id}</td><td>{e.action}</td><td>{e.actor}</td>
                  <td>{e.test_id ? <Link to={`/history/${e.test_id}`}>{e.test_id}</Link> : "—"}</td>
                  <td>{fmt(e.ts)}</td><td><Badge kind={e.outcome} /></td>
                  <td><code title={`prev ${e.prev_hash}`}>{e.event_hash?.slice(0, 12)}…</code></td>
                </tr>
              ))}
            </tbody>
          </table>
          <p className="muted">{data.total} matching events.</p>
        </section>
      )}
    </>
  );
}
