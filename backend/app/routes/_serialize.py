import json
from ..models import TestRun, User
from ..schemas import TestDetail, TestSummary


def exec_status(r: TestRun) -> str:
    """Stored execution status; derived from the legacy outcome for any row written before the columns existed."""
    return r.execution_status or ("ERROR" if r.outcome == "ERROR" else "COMPLETED")


def verdict(r: TestRun) -> str | None:
    if exec_status(r) == "ERROR":
        return None
    return r.security_verdict or (r.outcome if r.outcome != "ERROR" else None)


def severity(r: TestRun) -> str | None:
    """Stored severity; computed on the fly for a legacy row that has not been backfilled yet. None when execution failed."""
    if exec_status(r) == "ERROR":
        return None
    if r.severity:
        return r.severity
    from ..services import evaluator
    from ..services.testcases import CASES, custom_spec
    case = CASES.get(r.test_case_id) if r.test_case_id else None
    check = case.check if case else custom_spec(r.category, r.test_objective)[1]
    return evaluator.severity_for(verdict(r), check, case.severity if case else None)


def error_text(r: TestRun) -> str | None:
    if exec_status(r) != "ERROR":
        return None
    return r.error_message or r.explanation


def _base(r: TestRun) -> dict:
    return dict(execution_status=exec_status(r), security_verdict=verdict(r), severity=severity(r),
        test_id=r.test_id, test_case_id=r.test_case_id, test_name=r.test_name, category=r.category, provider=r.provider,
        model=r.model, outcome=r.outcome, mode=r.mode, defense_triggered=bool(r.defense_triggered),
        false_refusal=(r.category == "normal_request" and r.outcome == "FAIL"), run_group_id=r.run_group_id,
        duration_ms=r.duration_ms, created_at=r.created_at,
        trial_number=r.trial_number or 1, test_suite_version=r.test_suite_version,
    )


def summary(r: TestRun) -> TestSummary:
    return TestSummary(**_base(r))


def detail(r: TestRun, user: User) -> TestDetail:
    d = _base(r) | dict(prompt=r.prompt, response=r.response, explanation=r.explanation,
                        test_objective=r.test_objective, error_message=error_text(r),
                        human_review_status=r.human_review_status or "NOT_REVIEWED")
    if user.role in ("blue_team", "admin"):  # the active configuration is private to Blue Team (and Admin oversight)
        d["defense_config_id"] = r.defense_config_id
        d["defense_actions"] = json.loads(r.defense_actions) if r.defense_actions else []
    return TestDetail(**d)


def visible_filter(user: User):
    """SQL condition for records a role may see. Red and Blue Team artifacts are kept separate."""
    from sqlalchemy import true
    if user.role == "admin":
        return true()
    return TestRun.owner_role == user.role


def can_view(user: User, r: TestRun) -> bool:
    return user.role == "admin" or r.owner_role == user.role
