import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";

vi.mock("../services/api", () => ({ api: {
  presets: vi.fn(), saveDefenseConfig: vi.fn(), runComparison: vi.fn(), runSuite: vi.fn(), runTest: vi.fn(),
  adminOverview: vi.fn(), adminUsers: vi.fn(), adminUpdateUser: vi.fn(), adminCreateUser: vi.fn(),
  audit: vi.fn(), verifyAudit: vi.fn(), health: vi.fn(), aiHealth: vi.fn(), baseUrl: "http://x",
} }));
vi.mock("../services/auth", () => ({ useAuth: () => ({ user: { email: "admin@leakproof.local", role: "admin" } }) }));

import { api } from "../services/api";
import ProtectionWizard from "../components/ProtectionWizard";
import RedGuide from "../components/RedGuide";
import Admin from "../pages/Admin";

const PRESETS = { default: "recommended", presets: [
  { id: "basic", label: "Basic", summary: "Essential.", input_screen: false, hardened_prompt: true, output_redaction: true, output_contract: false },
  { id: "recommended", label: "Recommended", summary: "Default.", input_screen: true, hardened_prompt: true, output_redaction: true, output_contract: false },
  { id: "strict", label: "Strict", summary: "Most.", input_screen: true, hardened_prompt: true, output_redaction: true, output_contract: true }] };
const ACTIVE = { id: 4, name: "Recommended protection", input_screen: true, hardened_prompt: true, output_redaction: true, output_contract: false, policy_text: "", is_active: true, created_at: "2026-10-26T10:00:00Z", created_by: "blue" };
const M = (b, d, extra = {}) => ({ total: 11, PASS: 0, FAIL: 0, NEEDS_REVIEW: 0, ERROR: 0, NOT_APPLICABLE: 0, attack_successes: 0, ...b, ...extra });
const CMP = (o = {}) => ({ baseline_group_id: "g1", defended_group_id: "g2", defense_config_id: 4, baseline: M({ FAIL: 3, attack_successes: 3 }), defended: M({ FAIL: 1, attack_successes: 1 }),
  defense_effectiveness: 66.7, remaining_failures: [{ test_id: "T1", test_name: "Leak the code", category: "system_prompt_leakage", severity: "HIGH", explanation: "The code was disclosed." }],
  per_test: [{ test_case_id: "sp-001", test_name: "Leak the code", category: "system_prompt_leakage", baseline_outcome: "FAIL", defended_outcome: "FAIL", baseline_severity: "HIGH", defended_severity: "HIGH", defense_triggered: true }], caveats: [], ...o });
beforeEach(() => { vi.clearAllMocks(); api.presets.mockResolvedValue(PRESETS); });
const wrap = (ui) => render(<MemoryRouter>{ui}</MemoryRouter>);

describe("Blue Team guided protection", () => {
  it("shows the three presets with Recommended as default and the four steps", async () => {
    wrap(<ProtectionWizard cfg={{ active: null, history: [] }} cmp={null} canEdit onApplied={vi.fn()} onCompared={vi.fn()} />);
    const group = await screen.findByRole("radiogroup", { name: /protection level/i });
    expect(within(group).getAllByRole("radio")).toHaveLength(3);
    expect(within(group).getByRole("radio", { name: /Recommended/ })).toBeChecked();
    for (const t of ["Choose protection", "Apply protection", "Run security test", "Review results"]) expect(screen.getByRole("heading", { name: new RegExp(t, "i") })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Test My Protection" })).toBeDisabled();           // nothing applied yet
  });

  it("Apply Protection sends the preset's real mechanisms to the backend", async () => {
    api.saveDefenseConfig.mockResolvedValue({ id: 9 });
    wrap(<ProtectionWizard cfg={{ active: null, history: [] }} cmp={null} canEdit onApplied={vi.fn()} onCompared={vi.fn()} />);
    await userEvent.click(await screen.findByRole("radio", { name: /Strict/ }));
    await userEvent.click(screen.getByRole("button", { name: "Apply Protection" }));
    await waitFor(() => expect(api.saveDefenseConfig).toHaveBeenCalledWith({ name: "Strict protection", input_screen: true, hardened_prompt: true, output_redaction: true, output_contract: true, policy_text: "" }));
  });

  it("a failed save never claims success and says protection was NOT applied", async () => {
    api.saveDefenseConfig.mockRejectedValue(new Error("Server said no"));
    wrap(<ProtectionWizard cfg={{ active: null, history: [] }} cmp={null} canEdit onApplied={vi.fn()} onCompared={vi.fn()} />);
    await userEvent.click(await screen.findByRole("button", { name: "Apply Protection" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(/NOT applied.*Server said no/);
    expect(screen.queryByText(/saved by the server/i)).toBeNull();
    expect(screen.getByText(/No protection is active yet/)).toBeInTheDocument();
  });

  it("advanced checkboxes are tucked away and switching one marks the level Custom", async () => {
    wrap(<ProtectionWizard cfg={{ active: ACTIVE, history: [ACTIVE] }} cmp={null} canEdit onApplied={vi.fn()} onCompared={vi.fn()} />);
    await screen.findByRole("radiogroup");
    await userEvent.click(screen.getByText(/Advanced settings/));
    await userEvent.click(screen.getByRole("checkbox", { name: /Input Screen/ }));
    await waitFor(() => expect(screen.getAllByText("Custom").length).toBeGreaterThan(0));
    expect(screen.getByText(/changes that are not applied yet/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Test My Protection" })).toBeDisabled();           // must apply first
  });

  it("a double click starts only one comparison run", async () => {
    let done; api.runComparison.mockReturnValue(new Promise((r) => { done = r; }));
    const onCompared = vi.fn();
    wrap(<ProtectionWizard cfg={{ active: ACTIVE, history: [ACTIVE] }} cmp={null} canEdit onApplied={vi.fn()} onCompared={onCompared} />);
    const btn = await screen.findByRole("button", { name: "Test My Protection" });
    await waitFor(() => expect(btn).toBeEnabled());
    await userEvent.dblClick(btn);
    expect(api.runComparison).toHaveBeenCalledTimes(1);
    done(CMP()); await waitFor(() => expect(onCompared).toHaveBeenCalledTimes(1));
  });

  it("results use plain counts, list what to fix, and make no invented percentage when the baseline had no successful attacks", async () => {
    const { unmount } = wrap(<ProtectionWizard cfg={{ active: ACTIVE, history: [ACTIVE] }} cmp={CMP()} canEdit onApplied={vi.fn()} onCompared={vi.fn()} />);
    expect(await screen.findByText("What should I fix next?")).toBeInTheDocument();
    expect(screen.getByText("Leak the code", { selector: "a" })).toBeInTheDocument();
    expect(screen.getByText(/1 of 3 attack\(s\) still work/)).toBeInTheDocument();
    unmount();
    wrap(<ProtectionWizard cfg={{ active: ACTIVE, history: [ACTIVE] }} cmp={CMP({ baseline: M({}), defended: M({}), remaining_failures: [], defense_effectiveness: null, per_test: [] })} canEdit onApplied={vi.fn()} onCompared={vi.fn()} />);
    expect(await screen.findByText(/nothing for protection to improve yet/)).toBeInTheDocument();
    expect(screen.queryByText(/%/)).toBeNull();
  });

  it("flags incomplete runs and results from an older protection version", async () => {
    wrap(<ProtectionWizard cfg={{ active: ACTIVE, history: [ACTIVE] }} cmp={CMP({ defense_config_id: 2, defended: M({ ERROR: 2, FAIL: 1, attack_successes: 1 }) })} canEdit onApplied={vi.fn()} onCompared={vi.fn()} />);
    expect(await screen.findByText(/Incomplete: 2 test/)).toBeInTheDocument();
    expect(screen.getByText(/earlier protection version \(v2\)/)).toBeInTheDocument();
  });
});

describe("Admin console", () => {
  const users = { items: [
    { id: 1, email: "admin@leakproof.local", role: "admin", is_active: true, created_at: "2026-10-01T00:00:00Z", active_sessions: 1 },
    { id: 2, email: "blue@leakproof.local", role: "blue_team", is_active: true, created_at: "2026-10-01T00:00:00Z", active_sessions: 0 }] };
  it("overview shows real alerts and counts", async () => {
    api.adminOverview.mockResolvedValue({ users: { total: 3, active: 3, by_role: { red_team: 1, blue_team: 1, admin: 1 } }, tests_last_7_days: 5, execution_errors_last_7_days: 0, denied_last_7_days: 0, database: "ok",
      ai: { ok: false, provider: "ollama", model: "llama3.2:3b", detail: "Cannot reach Ollama" }, alerts: [{ level: "error", text: "The AI model is not reachable: Cannot reach Ollama" }], recent_tests: [] });
    wrap(<Admin />);
    expect(await screen.findByRole("alert")).toHaveTextContent(/not reachable/);
    expect(screen.getByText("3 of 3")).toBeInTheDocument();
  });
  it("cannot change own role, asks for confirmation before deactivating, and shows server refusals", async () => {
    api.adminOverview.mockResolvedValue({ users: { total: 2, active: 2, by_role: {} }, tests_last_7_days: 0, execution_errors_last_7_days: 0, denied_last_7_days: 0, database: "ok", ai: { ok: true }, alerts: [], recent_tests: [] });
    api.adminUsers.mockResolvedValue(users);
    api.adminUpdateUser.mockRejectedValue(new Error("This is the last active administrator"));
    wrap(<Admin />);
    await userEvent.click(await screen.findByRole("button", { name: "User Management" }));
    expect(await screen.findByLabelText("Role for admin@leakproof.local")).toBeDisabled();
    const deacts = screen.getAllByRole("button", { name: "Deactivate" });
    expect(deacts[0]).toBeDisabled();                       // yourself
    await userEvent.click(deacts[1]);
    expect(api.adminUpdateUser).not.toHaveBeenCalled();     // nothing happens before confirming
    const dlg = await screen.findByRole("alertdialog");
    await userEvent.click(within(dlg).getByRole("button", { name: "Deactivate" }));
    await waitFor(() => expect(api.adminUpdateUser).toHaveBeenCalledWith(2, { is_active: false }));
    expect(await screen.findByRole("alert")).toHaveTextContent(/last active administrator/);
  });
  it("lists every admin section and explains roles in plain English", async () => {
    api.adminOverview.mockResolvedValue({ users: { total: 1, active: 1, by_role: {} }, tests_last_7_days: 0, execution_errors_last_7_days: 0, denied_last_7_days: 0, database: "ok", ai: { ok: true }, alerts: [], recent_tests: [] });
    wrap(<Admin />);
    const nav = await screen.findByRole("navigation", { name: /admin sections/i });
    expect(within(nav).getAllByRole("button").map((b) => b.textContent)).toEqual(["Overview", "User Management", "Roles & Permissions", "Security Activity", "System Status"]);
    await userEvent.click(within(nav).getByRole("button", { name: "Roles & Permissions" }));
    expect(screen.getByText(/enforced by the server on every request/)).toBeInTheDocument();
  });
});

describe("Red Team guided testing", () => {
  const cases = [{ id: "sp-001", category: "system_prompt_leakage", name: "Leak", description: "Asks for the hidden code.", success_criteria: "The code is revealed.", remediation: "Add an output check.", availability: "implemented" },
    { id: "rc-001", category: "resource_consumption", name: "Huge", description: "x", success_criteria: "x", remediation: "x", availability: "requires:infrastructure" }];
  const R = (o = {}) => ({ test_id: "T9", test_case_id: "sp-001", test_name: "Leak", category: "system_prompt_leakage", execution_status: "COMPLETED", security_verdict: "FAIL", severity: "HIGH", explanation: "Disclosed.", response: "code LP-DEMO", ...o });
  it("lists only implemented categories, and disables Run when the model is down", async () => {
    wrap(<RedGuide cases={cases} model={{ ok: false, detail: "Cannot reach Ollama" }} checkModel={vi.fn()} onDone={vi.fn()} />);
    expect(screen.getByText("System-prompt leakage")).toBeInTheDocument();
    expect(screen.queryByText("Resource consumption")).toBeNull();
    expect(screen.getByRole("button", { name: "Run Security Test" })).toBeDisabled();
  });
  it("runs once on double click and explains each finding with evidence and a retest", async () => {
    let done; api.runSuite.mockReturnValue(new Promise((r) => { done = r; }));
    wrap(<RedGuide cases={cases} model={{ ok: true, provider: "ollama", model: "m" }} checkModel={vi.fn()} onDone={vi.fn()} />);
    await userEvent.dblClick(screen.getByRole("button", { name: "Run Security Test" }));
    expect(api.runSuite).toHaveBeenCalledTimes(1);
    done({ total: 1, counts: {}, trials: 1, results: [R()] });
    expect(await screen.findByText("1 vulnerability needs attention.")).toBeInTheDocument();
    for (const t of ["What we tested", "What happened", "Why it matters", "Evidence (the AI’s real answer)", "Suggested fix"]) expect(screen.getByText(t)).toBeInTheDocument();
    expect(screen.getByText("Unresolved")).toBeInTheDocument();
    api.runTest.mockResolvedValue(R({ test_id: "T10", security_verdict: "PASS", severity: "NONE" }));
    await userEvent.click(screen.getByRole("button", { name: /Retest this attack/ }));
    await waitFor(() => expect(api.runTest).toHaveBeenCalledWith({ test_case_id: "sp-001", mode: "auto", trials: 1 }));
    expect(await screen.findByText(/this retest:/)).toBeInTheDocument();
  });
  it("never says secure: a clean run still carries the limited-suite caveat, and an incomplete run is flagged", async () => {
    api.runSuite.mockResolvedValue({ total: 2, counts: {}, trials: 1, results: [R({ security_verdict: "PASS", severity: "NONE" }), R({ test_id: "T2", execution_status: "ERROR", security_verdict: null, severity: null })] });
    wrap(<RedGuide cases={cases} model={{ ok: true, provider: "o", model: "m" }} checkModel={vi.fn()} onDone={vi.fn()} />);
    await userEvent.click(screen.getByRole("button", { name: "Run Security Test" }));
    expect(await screen.findByText(/run was incomplete/)).toBeInTheDocument();
    expect(screen.getByText(/cannot prove an AI is secure/)).toBeInTheDocument();
  });
});
