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

const LABELS = { PASS: "Pass", FAIL: "Fail", NEEDS_REVIEW: "Needs review", ERROR: "Error", success: "Success", failure: "Failure", denied: "Denied", error: "Error" };
const CLASS = { PASS: "passed", FAIL: "failed", NEEDS_REVIEW: "review", ERROR: "err", denied: "failed", failure: "failed" };
export function Badge({ kind }) {
  return <span className={`badge ${CLASS[kind] || kind}`}>{LABELS[kind] || kind}</span>;
}

export const CATEGORY_LABELS = {
  prompt_injection: "Prompt injection",
  jailbreak: "Jailbreak resistance",
  data_leakage: "Sensitive-information leakage",
  instruction_conflict: "Instruction conflicts",
  normal_request: "Normal-request handling",
};
export const STATUS_OPTIONS = ["PASS", "FAIL", "NEEDS_REVIEW", "ERROR"];
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
