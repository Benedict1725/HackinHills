import { Link } from "react-router-dom";
import { Bar, BarChart, CartesianGrid, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { api } from "../services/api";
import { useApi } from "../services/useApi";
import { Badge, CATEGORY_LABELS, ErrorState, Loading, PageHeader, fmt } from "../components/ui";

export default function Overview() {
  const dash = useApi(api.dashboard);
  const health = useApi(api.health);
  const ai = useApi(api.aiHealth);

  if (dash.loading) return <Loading label="Loading dashboard…" />;
  if (dash.error) return <ErrorState message={dash.error} onRetry={() => { dash.retry(); health.retry(); ai.retry(); }} />;
  const d = dash.data;
  const stats = [
    ["Total tests", d.total_tests], ["Pass", d.passed], ["Fail", d.failed],
    ["Needs review", d.needs_review], ["Error", d.errors],
    ["Attack success rate", d.attack_success_rate == null ? "—" : `${d.attack_success_rate}%`],
    ["False refusals", d.false_refusals],
  ];
  const rate = (m) => (m.attack_success_rate == null ? "—" : `${m.attack_success_rate}%`);
  const chart = d.by_category.map((c) => ({ ...c, name: CATEGORY_LABELS[c.category] || c.category }));
  const dot = (s) => (s.error || (s.data && s.data.ok === false) ? "offline" : s.loading ? "checking" : "online");
  return (
    <>
      <PageHeader title="Overview" subtitle={`Live results from saved tests. Nothing on this page is sample data. Scope: ${d.scope_note}.`} />
      <section className="stats">
        {stats.map(([label, value]) => (
          <div className="card stat" key={label} title={label === "Attack success rate" ? d.attack_success_note : undefined}>
            <div className="stat-value">{value}</div><div className="muted">{label}</div>
          </div>
        ))}
        <div className="card stat">
          <div className="stat-value small"><span className={`dot ${dot(health)}`} />{health.error ? "Offline" : health.loading ? "Checking" : "Online"}</div>
          <div className="muted">Backend</div>
        </div>
        <div className="card stat">
          <div className="stat-value small"><span className={`dot ${dot(ai)}`} />{ai.loading ? "Checking" : ai.data?.ok ? "Connected" : "Unavailable"}</div>
          <div className="muted">AI model{ai.data?.model ? ` · ${ai.data.model}` : ""}</div>
        </div>
      </section>

      {d.total_tests === 0 ? (
        <div className="card"><h2>No test results yet</h2><p className="muted">Run a test or the full suite in the <Link to="/red-team">Red Team Console</Link> and results will appear here.</p></div>
      ) : (
        <>
          <section className="card">
            <h2>Outcomes by category</h2>
            <p className="muted">Attack success rate = Fail ÷ (Pass + Fail) across attack categories. Controls, Needs review and Error are excluded.</p>
            <div className="chart"><ResponsiveContainer width="100%" height="100%">
              <BarChart data={chart}>
                <CartesianGrid stroke="#1e3354" vertical={false} />
                <XAxis dataKey="name" stroke="#8aa0c0" tick={{ fontSize: 11 }} /><YAxis stroke="#8aa0c0" allowDecimals={false} />
                <Tooltip contentStyle={{ background: "#0f1e38", border: "1px solid #1e3354" }} /><Legend />
                <Bar dataKey="PASS" name="Pass" stackId="a" fill="#14b8a6" />
                <Bar dataKey="FAIL" name="Fail" stackId="a" fill="#f87171" />
                <Bar dataKey="NEEDS_REVIEW" name="Needs review" stackId="a" fill="#fbbf24" />
                <Bar dataKey="ERROR" name="Error" stackId="a" fill="#8aa0c0" />
              </BarChart>
            </ResponsiveContainer></div>
          </section>
          {d.by_mode.baseline.total > 0 && d.by_mode.defended.total > 0 && (
            <section className="card table-wrap">
              <h2>Baseline versus defended (all saved runs in scope)</h2>
              <table><thead><tr><th>Mode</th><th>Tests</th><th>Attack success rate</th><th>False refusal rate</th></tr></thead>
                <tbody>{["baseline", "defended"].map((k) => <tr key={k}><td>{k}</td><td>{d.by_mode[k].total}</td><td>{rate(d.by_mode[k])}</td><td>{d.by_mode[k].false_refusal_rate == null ? "—" : `${d.by_mode[k].false_refusal_rate}%`}</td></tr>)}</tbody></table>
              <p className="muted">Use the Blue Team Console for a like-for-like comparison of identical test cases.</p>
            </section>
          )}
          <section className="card">
            <h2>Recent test activity</h2>
            <div className="table-wrap"><table>
              <thead><tr><th>ID</th><th>Test</th><th>Outcome</th><th>Time</th></tr></thead>
              <tbody>{d.recent_activity.map((r) => (
                <tr key={r.test_id}><td><Link to={`/history/${r.test_id}`}>{r.test_id}</Link></td><td>{r.test_name}</td><td><Badge kind={r.outcome} /></td><td>{fmt(r.created_at)}</td></tr>
              ))}</tbody>
            </table></div>
          </section>
        </>
      )}
    </>
  );
}
