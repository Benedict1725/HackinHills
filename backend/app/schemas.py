from datetime import datetime
from typing import Literal
from pydantic import BaseModel, Field, field_validator, model_validator
from .config import MAX_OBJECTIVE_CHARS, MAX_PROMPT_CHARS
from .services.testcases import CATEGORIES

Status = Literal["PASS", "FAIL", "NEEDS_REVIEW", "NOT_APPLICABLE", "ERROR"]   # legacy combined `outcome`
ExecutionStatus = Literal["PENDING", "RUNNING", "COMPLETED", "ERROR"]            # did the model request complete?
SecurityVerdict = Literal["PASS", "FAIL", "NEEDS_REVIEW", "NOT_APPLICABLE"]      # security result (None until evaluated / on ERROR)
Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "NONE"]            # impact of a confirmed vulnerability (None on execution ERROR)
CategoryId = str


class HealthResponse(BaseModel):
    status: str
    database: str
    version: str
    time: datetime


class AIHealthResponse(BaseModel):
    ok: bool
    provider: str
    model: str | None
    detail: str
    checked_at: datetime


class CategoryOut(BaseModel):
    id: CategoryId
    label: str


class TestCaseOut(BaseModel):
    __test__ = False
    id: str
    category: CategoryId
    name: str
    description: str
    prompt: str
    severity: str
    success_criteria: str
    remediation: str
    owasp: list[str]
    availability: str


class TestCasesResponse(BaseModel):
    __test__ = False
    categories: list[CategoryOut]
    cases: list[TestCaseOut]
    custom_max_chars: int
    objective_max_chars: int = MAX_OBJECTIVE_CHARS


class RunTestRequest(BaseModel):
    """Either a predefined test_case_id, or a custom prompt plus category (not both)."""
    mode: Literal["auto", "baseline", "defended"] = "auto"
    test_case_id: str | None = Field(default=None, max_length=32)
    prompt: str | None = Field(default=None, max_length=MAX_PROMPT_CHARS)
    category: CategoryId | None = None
    test_objective: str | None = Field(default=None, max_length=MAX_OBJECTIVE_CHARS)   # optional; custom prompts only
    trials: int = Field(default=1, ge=1, le=25)

    @field_validator("prompt", "test_objective")
    @classmethod
    def _strip(cls, v):
        return v.strip() if v is not None else v

    @field_validator("category")
    @classmethod
    def _known_category(cls, v):
        if v is not None and v not in CATEGORIES:
            raise ValueError("Unknown category.")
        return v

    @model_validator(mode="after")
    def _one_mode(self):
        if self.test_case_id:
            if self.prompt or self.category or self.test_objective:
                raise ValueError("Send either test_case_id, or prompt with category, not both.")
        elif not (self.prompt and self.category):
            raise ValueError("Provide a test_case_id, or both a non-empty prompt and a category.")
        return self


class TestSummary(BaseModel):
    __test__ = False
    test_id: str
    test_case_id: str | None
    test_name: str | None
    category: str
    provider: str | None
    model: str | None
    outcome: Status
    execution_status: ExecutionStatus = "COMPLETED"
    security_verdict: SecurityVerdict | None = None
    severity: Severity | None = None
    mode: str
    defense_triggered: bool
    false_refusal: bool
    run_group_id: str | None
    duration_ms: int | None
    created_at: datetime
    trial_number: int = 1
    test_suite_version: str | None = None


class TestDetail(TestSummary):
    __test__ = False
    prompt: str
    response: str | None
    explanation: str | None
    test_objective: str | None = None
    error_message: str | None = None
    # Visible to Blue Team and Admin only (Red Team must not learn the private configuration):
    defense_config_id: int | None = None
    defense_actions: list[str] | None = None
    human_review_status: Literal["CONFIRMED", "DISPUTED", "NOT_REVIEWED"] = "NOT_REVIEWED"


class HumanReviewRequest(BaseModel):
    status: Literal["CONFIRMED", "DISPUTED"]


class TestListResponse(BaseModel):
    __test__ = False
    items: list[TestSummary]
    total: int
    limit: int
    offset: int


class RunSuiteRequest(BaseModel):
    mode: Literal["auto", "baseline", "defended"] = "auto"
    trials: int = Field(default=1, ge=1, le=25)


class SuiteResponse(BaseModel):
    run_group_id: str
    total: int
    counts: dict[str, int]
    results: list[TestDetail]
    trials: int = 1
    limitations: list[str] = []


class CategoryCounts(BaseModel):
    category: str
    PASS: int = 0
    FAIL: int = 0
    NEEDS_REVIEW: int = 0
    NOT_APPLICABLE: int = 0
    ERROR: int = 0
    confirmed_sample_count: int = 0
    attack_success_rate: float | None = None


class MetricsSummary(BaseModel):
    total: int
    PASS: int
    FAIL: int
    NEEDS_REVIEW: int
    ERROR: int
    attack_successes: int
    attack_success_rate: float | None
    control_tests: int
    false_refusals: int
    false_refusal_rate: float | None
    NOT_APPLICABLE: int = 0


class DashboardResponse(BaseModel):
    role: str
    scope_note: str
    total_tests: int
    passed: int
    failed: int
    needs_review: int
    errors: int
    not_applicable: int = 0
    by_severity: dict[str, int] = {}
    attack_success_rate: float | None
    false_refusals: int
    attack_success_note: str
    by_mode: dict[str, MetricsSummary]
    by_category: list[CategoryCounts]
    recent_activity: list[TestSummary]


class LoginRequest(BaseModel):
    email: str = Field(min_length=3, max_length=200)
    password: str = Field(min_length=1, max_length=200)


class UserOut(BaseModel):
    email: str
    role: str


class LoginResponse(BaseModel):
    token: str
    expires_at: datetime
    user: UserOut


class DefenseConfigIn(BaseModel):
    name: str = Field(default="Blue Team policy", min_length=1, max_length=100)
    input_screen: bool = True
    hardened_prompt: bool = True
    output_redaction: bool = True
    output_contract: bool = True
    policy_text: str = Field(default="", max_length=1000)

    @field_validator("name", "policy_text")
    @classmethod
    def _strip(cls, v):
        return v.strip()


class DefenseConfigOut(BaseModel):
    id: int
    name: str
    input_screen: bool
    hardened_prompt: bool
    output_redaction: bool
    output_contract: bool
    policy_text: str
    is_active: bool
    created_by: str | None
    created_at: datetime


class DefenseConfigResponse(BaseModel):
    active: DefenseConfigOut | None
    history: list[DefenseConfigOut]


class ComparisonResponse(BaseModel):
    baseline_group_id: str
    defended_group_id: str
    defense_config_id: int | None
    baseline: MetricsSummary
    defended: MetricsSummary
    defense_effectiveness: float | None
    effectiveness_formula: str = "(baseline successful attacks - defended successful attacks) / baseline successful attacks x 100"
    remaining_failures: list[dict]
    per_test: list[dict]
    caveats: list[str]


class AuditEventOut(BaseModel):
    id: int
    ts: str | None
    actor: str
    action: str
    test_id: str | None
    outcome: str
    details: dict | None
    prev_hash: str | None
    event_hash: str | None


class AuditListResponse(BaseModel):
    items: list[AuditEventOut]
    total: int


class VerifyResponse(BaseModel):
    result: Literal["VERIFIED", "INTEGRITY FAILURE"]
    events_checked: int
    head_hash: str | None
    first_inconsistency: dict | None
    note: str


# ---- Shared Red Team findings (Blue Team view) --------------------------------------------------------------
class FindingOut(BaseModel):
    """A persisted Red Team test, as shared with Blue Team. Status/vulnerability are derived from the stored outcome."""
    test_id: str
    test_case_id: str | None
    test_name: str | None
    category: str
    prompt: str
    provider: str | None
    model: str | None
    response: str | None
    execution_status: ExecutionStatus                   # ERROR = the model call/pipeline failed; says nothing about security
    security_verdict: SecurityVerdict | None            # None when execution did not complete
    test_objective: str | None = None
    outcome: Status                                     # legacy combined value (verdict, or ERROR)
    vulnerability: Literal["detected", "not_detected", "inconclusive", "not_applicable", "unknown"]
    severity: Severity | None                           # evidence-based; None when execution failed
    explanation: str | None
    error: str | None                                   # safe provider/pipeline error message when execution failed
    original_mode: str                                  # baseline | defended: how Red Team ran it
    created_at: datetime
    duration_ms: int | None
    retest_count: int = 0


class FindingListResponse(BaseModel):
    items: list[FindingOut]
    total: int
    limit: int
    offset: int


class RetestAssessment(BaseModel):
    effect: Literal["blocked", "mitigated", "not_mitigated", "worse", "not_applicable", "inconclusive", "false_refusal", "error", "no_verdict"]
    summary: str
    vulnerable_before: bool | None
    vulnerable_after: bool | None
    severity_before: Severity | None
    severity_after: Severity | None
    responses_identical: bool | None = None             # original vs defended response text; None if either is missing
    notes: list[str] = []


class RetestOut(BaseModel):
    retest_id: str                                      # test_id of the persisted retest record
    finding_id: str
    defense_config_id: int | None
    defense_actions: list[str]
    execution_status: ExecutionStatus
    security_verdict: SecurityVerdict | None
    outcome: Status
    response: str | None
    explanation: str | None
    error: str | None
    duration_ms: int | None
    retested_at: datetime
    assessment: RetestAssessment
    original: FindingOut                                # the untouched original finding, for side-by-side comparison


class FindingDetailResponse(BaseModel):
    finding: FindingOut
    retests: list[RetestOut]
