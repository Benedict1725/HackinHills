"""Export saved evaluation evidence without exporting synthetic secrets verbatim."""
from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session
from ..database import get_db
from ..models import DefenseConfig, TestRun, User
from ..services import metrics
from ..services.auth import current_user
from ..services.defenses import protect_output
from ..services.testcases import CAPABILITY_NOTES, SUITE_VERSION
from . import _serialize as ser

router = APIRouter(prefix="/api", tags=["reports"])


@router.get("/reports/evaluation")
def evaluation_report(user: User = Depends(current_user), db: Session = Depends(get_db)):
    """JSON is deliberately portable: users may save it directly or feed it to reporting tools."""
    rows = db.scalars(select(TestRun).where(TestRun.is_demo.is_(False), ser.visible_filter(user)).order_by(TestRun.id)).all()
    outcomes = []
    for row in rows:
        evidence, _ = protect_output(row.response or "")
        outcomes.append({
            "test_id": row.test_id, "test_case_id": row.test_case_id, "test_name": row.test_name,
            "category": row.category, "outcome": row.outcome, "evaluator_explanation": row.explanation,
            "sanitized_evidence": evidence, "provider": row.provider, "model": row.model,
            "model_digest": row.model_digest, "mode": row.mode, "trial_number": row.trial_number or 1,
            "test_suite_version": row.test_suite_version, "defense_config_id": row.defense_config_id,
            "defense_actions": [] if user.role == "red_team" else (row.defense_actions or "[]"),
            "timestamp": row.created_at.isoformat(), "latency_ms": row.duration_ms,
        })
    configs = []
    if user.role in ("blue_team", "admin"):
        configs = [{"id": c.id, "name": c.name, "created_at": c.created_at.isoformat(), "active": c.is_active}
                   for c in db.scalars(select(DefenseConfig).order_by(DefenseConfig.id)).all()]
    return {
        "report_version": "1.0", "suite_version": SUITE_VERSION, "generated_for_role": user.role,
        "metrics": metrics.summarize(rows), "outcomes": outcomes, "defense_configurations": configs,
        "limitations": [
            "Confirmed rates use only PASS and FAIL; ambiguous and execution-error outcomes remain visible but are excluded.",
            "This is controlled synthetic-canary testing, not a universal model safety score.",
            *[f"{key}: {note}" for key, note in CAPABILITY_NOTES.items()],
        ],
    }
