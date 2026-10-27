from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session
from ..database import get_db
from ..models import TestRun, User
from ..schemas import CategoryCounts, DashboardResponse
from ..services import metrics
from ..services.auth import current_user
from . import _serialize as ser

router = APIRouter(prefix="/api", tags=["dashboard"])
SCOPE = {"red_team": "Red Team results only", "blue_team": "Blue Team evaluation runs only", "admin": "All results (administrator oversight)"}


@router.get("/dashboard", response_model=DashboardResponse)
def dashboard(user: User = Depends(current_user), db: Session = Depends(get_db)):
    """Every number is computed from saved test runs visible to the caller's role. Nothing is demo or estimated."""
    rows = db.scalars(select(TestRun).where(TestRun.is_demo.is_(False), ser.visible_filter(user)).order_by(TestRun.id.desc())).all()
    cats: dict[str, CategoryCounts] = {}
    for r in rows:
        c = cats.setdefault(r.category, CategoryCounts(category=r.category))
        if r.outcome in ("PASS", "FAIL", "NEEDS_REVIEW", "NOT_APPLICABLE", "ERROR"):
            setattr(c, r.outcome, getattr(c, r.outcome) + 1)
    for c in cats.values():
        c.confirmed_sample_count = c.PASS + c.FAIL
        if metrics.is_attack(c.category) and c.confirmed_sample_count:
            c.attack_success_rate = round(100 * c.FAIL / c.confirmed_sample_count, 1)
    overall = metrics.summarize(rows)
    by_sev: dict[str, int] = {}
    for r in rows:
        sv = ser.severity(r)
        if sv: by_sev[sv] = by_sev.get(sv, 0) + 1
    return DashboardResponse(
        role=user.role, scope_note=SCOPE[user.role], total_tests=overall["total"], passed=overall["PASS"], failed=overall["FAIL"],
        needs_review=overall["NEEDS_REVIEW"], errors=overall["ERROR"], not_applicable=overall["NOT_APPLICABLE"], by_severity=by_sev, attack_success_rate=overall["attack_success_rate"],
        false_refusals=overall["false_refusals"],
        attack_success_note="FAIL / (PASS + FAIL) across attack categories. Controls, NEEDS_REVIEW and ERROR are excluded.",
        by_mode={m: metrics.summarize([r for r in rows if r.mode == m]) for m in ("baseline", "defended")},
        by_category=list(cats.values()), recent_activity=[ser.summary(r) for r in rows[:8]],
    )
