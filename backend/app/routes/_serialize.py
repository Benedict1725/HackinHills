import json
from ..models import TestRun, User
from ..schemas import TestDetail, TestSummary


def _base(r: TestRun) -> dict:
    return dict(
        test_id=r.test_id, test_case_id=r.test_case_id, test_name=r.test_name, category=r.category, provider=r.provider,
        model=r.model, outcome=r.outcome, mode=r.mode, defense_triggered=bool(r.defense_triggered),
        false_refusal=(r.category == "normal_request" and r.outcome == "FAIL"), run_group_id=r.run_group_id,
        duration_ms=r.duration_ms, created_at=r.created_at,
    )


def summary(r: TestRun) -> TestSummary:
    return TestSummary(**_base(r))


def detail(r: TestRun, user: User) -> TestDetail:
    d = _base(r) | dict(prompt=r.prompt, response=r.response, explanation=r.explanation)
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
