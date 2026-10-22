from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from ..config import MAX_PROMPT_CHARS
from ..database import get_db
from ..models import TestRun, User
from ..schemas import (CategoryId, CategoryOut, RunSuiteRequest, RunTestRequest, Status, SuiteResponse, TestCaseOut,
                       TestCasesResponse, TestDetail, TestListResponse)
from ..services import defense_store, runner
from ..services.auth import current_user, deny_record_access, require_roles
from ..services.evaluator import STATUSES
from ..services.testcases import CASES, CATEGORIES, SUITE
from . import _serialize as ser
from .ai import get_provider_factory

router = APIRouter(prefix="/api", tags=["tests"])
BUSY = HTTPException(status_code=429, detail="Another test is already running. Wait for it to finish and try again.")


def unavailable(e):
    return HTTPException(status_code=503, detail=f"The AI model is unavailable: {e.message}")


@router.get("/test-cases", response_model=TestCasesResponse)
def test_cases(user: User = Depends(current_user)):
    return TestCasesResponse(
        categories=[CategoryOut(id=k, label=v) for k, v in CATEGORIES.items()],
        cases=[TestCaseOut(id=c.id, category=c.category, name=c.name, description=c.description, prompt=c.user) for c in SUITE],
        custom_max_chars=MAX_PROMPT_CHARS,
    )


@router.post("/tests/run", response_model=TestDetail, status_code=201)
def run_test(req: RunTestRequest, user: User = Depends(require_roles("red_team")), db: Session = Depends(get_db),
             factory=Depends(get_provider_factory)):
    mode, cfg = defense_store.resolve(db, req.mode)
    try:
        if req.test_case_id:
            case = CASES.get(req.test_case_id)
            if not case:
                raise HTTPException(status_code=404, detail=f"Unknown test case '{req.test_case_id}'.")
            row = runner.run_case(db, factory, case, user, mode, cfg)
        else:
            row = runner.run_custom(db, factory, req.prompt, req.category, user, mode, cfg)
    except runner.BusyError:
        raise BUSY
    return ser.detail(row, user)


@router.post("/tests/run-suite", response_model=SuiteResponse)
def run_suite(req: RunSuiteRequest | None = None, user: User = Depends(require_roles("red_team", "blue_team")),
              db: Session = Depends(get_db), factory=Depends(get_provider_factory)):
    mode, cfg = defense_store.resolve(db, (req or RunSuiteRequest()).mode)
    try:
        gid, rows = runner.run_suite(db, factory, user, mode, cfg)
    except runner.BusyError:
        raise BUSY
    except runner.ProviderUnavailable as e:
        raise unavailable(e)
    counts = {s: sum(r.outcome == s for r in rows) for s in STATUSES}
    return SuiteResponse(run_group_id=gid, total=len(rows), counts=counts, results=[ser.detail(r, user) for r in rows])


@router.get("/tests", response_model=TestListResponse)
def list_tests(category: CategoryId | None = None, status: Status | None = None,
               limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0),
               user: User = Depends(current_user), db: Session = Depends(get_db)):
    q = select(TestRun).where(TestRun.is_demo.is_(False), ser.visible_filter(user))
    if category: q = q.where(TestRun.category == category)
    if status: q = q.where(TestRun.outcome == status)
    total = db.scalar(select(func.count()).select_from(q.subquery()))
    rows = db.scalars(q.order_by(TestRun.created_at.desc(), TestRun.id.desc()).limit(limit).offset(offset)).all()
    return TestListResponse(items=[ser.summary(r) for r in rows], total=total, limit=limit, offset=offset)


@router.get("/tests/{test_id}", response_model=TestDetail)
def get_test(test_id: str, user: User = Depends(current_user), db: Session = Depends(get_db)):
    row = db.scalar(select(TestRun).where(TestRun.test_id == test_id[:32]))
    if not row:
        raise HTTPException(status_code=404, detail="Test not found.")
    if not ser.can_view(user, row):
        deny_record_access(db, user, "test", row.test_id)  # records the attempt, then 403
    return ser.detail(row, user)
