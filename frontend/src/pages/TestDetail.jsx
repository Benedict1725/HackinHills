import { useCallback } from "react";
import { Link, useParams } from "react-router-dom";
import { api } from "../services/api";
import { useApi } from "../services/useApi";
import { CATEGORY_LABELS, ErrorState, Loading, PageHeader, StatusPair, fmt, secs } from "../components/ui";

export default function TestDetail() {
  const { id } = useParams();
  const fetcher = useCallback(() => api.test(id), [id]);
  const { data: t, error, loading, retry } = useApi(fetcher);
  if (loading) return <Loading />;
  if (error) return <ErrorState message={error} onRetry={retry} />;
  return (
    <>
      <PageHeader title={t.test_id} subtitle={t.test_name} />
      <p><Link to="/history">Back to history</Link></p>
      <section className="card">
        <p><StatusPair executionStatus={t.execution_status} verdict={t.security_verdict} severity={t.severity ?? null} /></p>
        {t.error_message && <div className="fd-err" role="alert">Execution error: {t.error_message}</div>}
        <p><b>Reason:</b> {t.explanation}</p>
        <dl>
          <dt>Category</dt><dd>{CATEGORY_LABELS[t.category] || t.category}</dd>
          {t.test_objective && <><dt>Test objective</dt><dd>{t.test_objective}</dd></>}
          <dt>Model</dt><dd>{t.model ? `${t.provider}/${t.model}` : "—"}</dd>
          <dt>Defenses</dt><dd>{t.mode === "defended" ? (t.defense_triggered ? "Applied, and a defense triggered" : "Applied, none triggered") : "Not applied (baseline)"}</dd>
          {t.defense_actions && <><dt>Defense actions (Blue Team view)</dt><dd>{t.defense_actions.join(", ") || "none"}{t.defense_config_id ? ` · config v${t.defense_config_id}` : ""}</dd></>}
          <dt>Duration</dt><dd>{secs(t.duration_ms)}</dd>
          <dt>Timestamp</dt><dd>{fmt(t.created_at)}</dd>
        </dl>
      </section>
      <section className="grid2">
        <div className="card"><h2>Prompt</h2><pre>{t.prompt}</pre></div>
        <div className="card"><h2>Model response</h2>{t.response ? <pre>{t.response}</pre> : <p className="muted">No response was received.</p>}</div>
      </section>
    </>
  );
}
