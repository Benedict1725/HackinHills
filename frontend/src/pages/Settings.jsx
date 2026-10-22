import { api } from "../services/api";
import { useApi } from "../services/useApi";
import { ErrorState, Loading, PageHeader } from "../components/ui";

export default function Settings() {
  const { data, error, loading, retry } = useApi(api.health);
  const ai = useApi(api.aiHealth);
  return (
    <>
      <PageHeader title="Settings" />
      <section className="card">
        <h2>Backend connection</h2>
        {loading ? <Loading /> : error ? <ErrorState message={error} onRetry={retry} /> : (
          <dl>
            <dt>Status</dt><dd><span className="dot online" /> {data.status}</dd>
            <dt>Database</dt><dd>{data.database}</dd>
            <dt>API URL</dt><dd>{api.baseUrl}</dd>
          </dl>
        )}
      </section>
      <section className="card">
        <h2>AI provider</h2>
        {ai.loading ? <Loading label="Checking model…" /> : ai.error ? <ErrorState message={ai.error} onRetry={ai.retry} /> : (
          <>
            <p><span className={`dot ${ai.data.ok ? "online" : "offline"}`} />{ai.data.ok ? "Connected" : "Not connected"}</p>
            <dl><dt>Provider</dt><dd>{ai.data.provider}</dd><dt>Model</dt><dd>{ai.data.model || "(not set)"}</dd><dt>Detail</dt><dd>{ai.data.detail}</dd></dl>
            <p className="muted">Provider and model are set in backend/.env. API keys never reach the browser.</p>
            <button className="btn" onClick={ai.retry}>Recheck</button>
          </>
        )}
      </section>
      <section className="card">
        <h2>Application</h2>
        <dl><dt>Name</dt><dd>LeakProof AI</dd><dt>Version</dt><dd>0.3.0 (Day 3: defenses, access control, audit)</dd></dl>
      </section>
    </>
  );
}
