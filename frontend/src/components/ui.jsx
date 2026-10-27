export function Loading({ label = "Loading…" }) {
  return <div className="state" role="status">{label}</div>;
}

export function ErrorState({ message, onRetry }) {
  return (
    <div className="state error" role="alert">
      <p>{message}</p>
      <button className="btn" onClick={onRetry}>Retry</button>
    </div>
  );
}

export function DemoBanner({ children }) {
  return <div className="demo-banner">{children || "Demo data. These are not real AI test results."}</div>;
}

const LABELS = { PASS: "Pass", FAIL: "Fail", NEEDS_REVIEW: "Needs review", NOT_APPLICABLE: "Not applicable", ERROR: "Error", success: "Success", failure: "Failure", denied: "Denied", error: "Error" };
const CLASS = { PASS: "passed", FAIL: "failed", NEEDS_REVIEW: "review", NOT_APPLICABLE: "na", ERROR: "exec-err", denied: "failed", failure: "failed" };
export function Badge({ kind }) {
  return <span className={`badge ${CLASS[kind] || kind}`}>{LABELS[kind] || kind}</span>;
}

// Execution status = did the model request complete? Security verdict = what the evaluator concluded. Never merged into one badge.
const EXEC_LABEL = { COMPLETED: "Completed", ERROR: "Error", RUNNING: "Running", PENDING: "Pending" };
const EXEC_CLASS = { COMPLETED: "exec-ok", ERROR: "exec-err", RUNNING: "review", PENDING: "review" };
export function ExecBadge({ status }) {
  return <span className={`badge ${EXEC_CLASS[status] || "na"}`}>{EXEC_LABEL[status] || status || "Unknown"}</span>;
}
export function VerdictBadge({ verdict, executionStatus }) {
  if (!verdict) return <span className="badge na">{executionStatus === "ERROR" ? "Not evaluated" : "Pending"}</span>;
  return <Badge kind={verdict} />;
}
// Severity = impact of a CONFIRMED vulnerability. Always text, never colour alone. null (execution error) renders as an em dash.
export const SEVERITY_OPTIONS = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "NONE"];
export const VERDICT_OPTIONS = ["PASS", "FAIL", "NEEDS_REVIEW", "NOT_APPLICABLE"];
export const EXEC_OPTIONS = ["PENDING", "RUNNING", "COMPLETED", "ERROR"];
const SEV_LABEL = { CRITICAL: "Critical", HIGH: "High", MEDIUM: "Medium", LOW: "Low", INFO: "Info", NONE: "None" };
export function SeverityBadge({ severity }) {
  if (!severity) return <span className="badge na" title="No severity: execution did not complete">—</span>;
  return <span className={`badge sev-${severity.toLowerCase()}`}>{SEV_LABEL[severity] || severity}</span>;
}
// Both statuses side by side, with labels, so one is never mistaken for the other.
export function StatusPair({ executionStatus, verdict, severity, showSeverity = false }) {
  return <span className="status-pair"><span>Execution: <ExecBadge status={executionStatus} /></span> <span>Security verdict: <VerdictBadge verdict={verdict} executionStatus={executionStatus} /></span>{(showSeverity || severity !== undefined) && <> <span>Severity: <SeverityBadge severity={severity} /></span></>}</span>;
}

export const CATEGORY_LABELS = {
  prompt_injection: "Prompt injection",
  jailbreak: "Jailbreak resistance",
  data_leakage: "Sensitive-information leakage",
  instruction_conflict: "Instruction conflicts",
  normal_request: "Normal-request handling",
  system_prompt_leakage: "System-prompt leakage",
  improper_output_handling: "Improper output handling",
  misinformation: "Misinformation",
  resource_consumption: "Resource consumption",
  miscellaneous: "General / Miscellaneous",
};
export const STATUS_OPTIONS = ["PASS", "FAIL", "NEEDS_REVIEW", "NOT_APPLICABLE", "ERROR"];
export const secs = (ms) => (ms == null ? "—" : `${(ms / 1000).toFixed(1)}s`);

export const fmt = (iso) => new Date(iso).toLocaleString();

export function PageHeader({ title, subtitle }) {
  return (
    <header className="page-header">
      <h1>{title}</h1>
      {subtitle && <p>{subtitle}</p>}
    </header>
  );
}
