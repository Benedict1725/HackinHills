"""Shared Red Team findings for Blue Team.

Sharing rule (documented, explicit): LeakProof has no organization/tenant model, so the whole deployment is one
demo workspace. Inside it, ONLY these roles may read Red Team *findings* (non-demo test runs owned by red_team,
excluding Blue Team retests): blue_team and admin. Only blue_team may retest. Red Team gets no access to this
router, and nothing here changes visible_filter(), so /api/tests and the dashboards keep their existing isolation.
"""
import json
from fastapi import APIRouter, Depends, HTTPException, Path, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from ..database import get_db
from ..models import TestRun, User
from ..schemas import ExecutionStatus, SecurityVerdict, Severity, FindingDetailResponse, FindingListResponse, FindingOut, RetestAssessment, RetestOut
from ..services import audit, defense_store, evaluator, runner
from ..services.auth import require_roles
from ..services.testcases import CASES
from .ai import get_provider_factory
from . import _serialize as ser
from .tests import BUSY

router = APIRouter(prefix="/api/blue-team", tags=["blue-team-findings"])
FINDING_READERS = ("blue_team", "admin")
TestId = Path(min_length=1, max_length=32, pattern=r"^[A-Za-z0-9-]+$")


def finding_filter():
    """SQL condition that defines a shareable finding. Deliberately separate from visible_filter()."""
    return (TestRun.owner_role == "red_team", TestRun.is_demo.is_(False), TestRun.parent_test_id.is_(None))


def _vulnerable(row: TestRun) -> bool | None:
    v = ser.verdict(row)
    return True if v == evaluator.FAIL else False if v == evaluator.PASS else None


def _severity(row: TestRun) -> str | None:
    return ser.severity(row)


def _vuln_label(row: TestRun) -> str:
    return {"FAIL": "detected", "PASS": "not_detected", "NEEDS_REVIEW": "inconclusive", "NOT_APPLICABLE": "not_applicable"}.get(ser.verdict(row) or "", "unknown")


def finding_out(row: TestRun, retest_count: int = 0) -> FindingOut:
    return FindingOut(
        test_id=row.test_id, test_case_id=row.test_case_id, test_name=row.test_name, category=row.category, prompt=row.prompt,
        provider=row.provider, model=row.model, response=row.response,
        execution_status=ser.exec_status(row), security_verdict=ser.verdict(row), test_objective=row.test_objective,
        outcome=row.outcome, vulnerability=_vuln_label(row), severity=_severity(row), explanation=row.explanation, error=ser.error_text(row),
        original_mode=row.mode, created_at=row.created_at, duration_ms=row.duration_ms, retest_count=retest_count)


def assess(orig: TestRun, defd: TestRun) -> RetestAssessment:
    """Judge the retest from the real evaluated results, never from which toggles are on."""
    actions = json.loads(defd.defense_actions) if defd.defense_actions else []
    input_blocked = any(a.startswith("input_screen:blocked") for a in actions)
    ov, dv = ser.verdict(orig), ser.verdict(defd)
    same = (orig.response == defd.response) if (orig.response is not None and defd.response is not None) else None
    notes = []
    if orig.mode == "defended":
        notes.append("Red Team ran the original with defenses already on, so this compares two defended runs.")
    if orig.test_case_id is None and orig.category == "miscellaneous":
        notes.append("General prompt: it has no security-specific criterion unless a test objective was set, so the two responses are compared but no vulnerability is claimed.")
    elif orig.test_case_id is None:
        notes.append("Custom prompt: only its category's synthetic-canary check can confirm a vulnerability.")
    if same is True:
        notes.append("The defended response is identical to the original response.")
    elif same is False and defd.execution_status != "ERROR":
        notes.append("The defended response differs from the original response (this can also come from model variability).")
    if ser.exec_status(defd) == "ERROR":
        effect, summary = "error", "The retest could not execute, so the defenses were not evaluated."
    elif input_blocked:
        if orig.category in ("normal_request", "miscellaneous"):
            effect, summary = "false_refusal", "The input screen blocked an ordinary request before it reached the model (possible false refusal)."
        else:
            effect, summary = "blocked", "The input screen stopped the prompt before it reached the model."
    elif ser.exec_status(orig) == "ERROR":
        effect, summary = "inconclusive", "The original run failed, so there is no earlier result to compare against."
    elif ov == evaluator.NOT_APPLICABLE or dv == evaluator.NOT_APPLICABLE:
        effect, summary = "no_verdict", "This prompt has no applicable security verdict, so the defenses cannot be scored. Compare the two responses yourself."
    elif ov == evaluator.FAIL and dv == evaluator.PASS:
        effect, summary = "mitigated", "The original run was vulnerable; the defended response passed the same check."
    elif ov == evaluator.FAIL and dv == evaluator.FAIL:
        effect, summary = "not_mitigated", "The vulnerability is still present with the saved defenses."
    elif ov == evaluator.PASS and dv == evaluator.FAIL:
        effect, summary = "worse", "The original run passed but the defended run failed. Check for model variability or a defense side effect."
    elif ov == evaluator.PASS and dv == evaluator.PASS:
        effect, summary = "not_applicable", "No vulnerability was detected originally, so there was nothing to mitigate."
    else:
        effect, summary = "inconclusive", "The evaluator cannot reliably decide whether the attack succeeded; a human should review both responses."
    return RetestAssessment(effect=effect, summary=summary, vulnerable_before=_vulnerable(orig),
                            vulnerable_after=_vulnerable(defd), severity_before=_severity(orig),
                            severity_after=_severity(defd), responses_identical=same, notes=notes)


def retest_out(orig: TestRun, rt: TestRun, retest_count: int) -> RetestOut:
    return RetestOut(
        retest_id=rt.test_id, finding_id=orig.test_id, defense_config_id=rt.defense_config_id,
        defense_actions=json.loads(rt.defense_actions) if rt.defense_actions else [],
        execution_status=ser.exec_status(rt), security_verdict=ser.verdict(rt), outcome=rt.outcome, response=rt.response,
        explanation=rt.explanation, error=ser.error_text(rt), duration_ms=rt.duration_ms, retested_at=rt.created_at,
        assessment=assess(orig, rt), original=finding_out(orig, retest_count))


def _get_finding(db: Session, test_id: str) -> TestRun:
    row = db.scalar(select(TestRun).where(TestRun.test_id == test_id, *finding_filter()))
    if not row:
        raise HTTPException(status_code=404, detail="Finding not found.")
    return row


def _retests(db: Session, test_id: str) -> list[TestRun]:
    return list(db.scalars(select(TestRun).where(TestRun.parent_test_id == test_id).order_by(TestRun.id.desc())).all())


@router.get("/findings", response_model=FindingListResponse)
def list_findings(limit: int = Query(25, ge=1, le=100), offset: int = Query(0, ge=0),
                  severity: Severity | None = None, verdict: SecurityVerdict | None = None, category: str | None = Query(None, max_length=64),
                  execution_status: ExecutionStatus | None = None,
                  user: User = Depends(require_roles(*FINDING_READERS)), db: Session = Depends(get_db)):
    q = select(TestRun).where(*finding_filter())
    if category: q = q.where(TestRun.category == category)
    if execution_status == "ERROR": q = q.where((TestRun.execution_status == "ERROR") | ((TestRun.execution_status.is_(None)) & (TestRun.outcome == "ERROR")))
    elif execution_status: q = q.where(TestRun.execution_status == execution_status)
    if verdict: q = q.where(TestRun.security_verdict == verdict)
    if severity: q = q.where(TestRun.severity == severity)
    total = db.scalar(select(func.count()).select_from(q.subquery()))
    rows = db.scalars(q.order_by(TestRun.id.desc()).limit(limit).offset(offset)).all()
    counts = dict(db.execute(select(TestRun.parent_test_id, func.count()).where(TestRun.parent_test_id.in_([r.test_id for r in rows]))
                             .group_by(TestRun.parent_test_id)).all()) if rows else {}
    return FindingListResponse(items=[finding_out(r, counts.get(r.test_id, 0)) for r in rows], total=total, limit=limit, offset=offset)


@router.get("/findings/{test_id}", response_model=FindingDetailResponse)
def get_finding(test_id: str = TestId, user: User = Depends(require_roles(*FINDING_READERS)), db: Session = Depends(get_db)):
    row = _get_finding(db, test_id)
    rts = _retests(db, row.test_id)
    return FindingDetailResponse(finding=finding_out(row, len(rts)), retests=[retest_out(row, r, len(rts)) for r in rts])


@router.post("/findings/{test_id}/retest", response_model=RetestOut, status_code=201)
def retest_finding(test_id: str = TestId, user: User = Depends(require_roles("blue_team")), db: Session = Depends(get_db),
                   factory=Depends(get_provider_factory)):
    row = _get_finding(db, test_id)
    _, cfg = defense_store.resolve(db, "defended")  # 409 if Blue Team has not saved a configuration yet
    try:
        rt = runner.run_retest(db, factory, row, user, cfg)
    except runner.BusyError:
        raise BUSY
    audit.record(db, action="finding.retest", actor=user.email, outcome="success" if ser.exec_status(rt) != "ERROR" else "failure",
                 test_id=rt.test_id, details={"role": user.role, "finding_id": row.test_id, "defense_config_id": cfg.config_id,
                                              "evaluation": rt.outcome})
    return retest_out(row, rt, len(_retests(db, row.test_id)))
