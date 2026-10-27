from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session
from ..database import get_db
from ..models import DefenseConfig, TestRun, User
from ..schemas import ComparisonResponse, DefenseConfigIn, DefenseConfigOut, DefenseConfigResponse
from ..services import audit, defense_store, metrics, runner
from ..services.auth import require_roles
from .ai import get_provider_factory
from .tests import BUSY, unavailable

router = APIRouter(prefix="/api", tags=["defense"])


def _out(c: DefenseConfig, db: Session) -> DefenseConfigOut:
    u = db.get(User, c.created_by) if c.created_by else None
    return DefenseConfigOut(id=c.id, name=c.name, input_screen=bool(c.input_validation), hardened_prompt=bool(c.hardened_prompt),
                            output_redaction=bool(c.output_checking), output_contract=bool(c.output_contract), policy_text=c.policy_text or "", is_active=bool(c.is_active),
                            created_by=u.email if u else None, created_at=c.created_at)


@router.get("/defense/presets")
def presets(user: User = Depends(require_roles("blue_team", "admin"))):
    """Documented preset -> mechanism mapping (single source of truth for the UI)."""
    from ..services.defenses import PRESETS
    return {"default": "recommended", "presets": [{"id": k, **v} for k, v in PRESETS.items()]}


@router.get("/defense/config", response_model=DefenseConfigResponse)
def get_config(user: User = Depends(require_roles("blue_team", "admin")), db: Session = Depends(get_db)):
    active = defense_store.get_active(db)
    hist = db.scalars(select(DefenseConfig).order_by(DefenseConfig.id.desc()).limit(10)).all()
    return DefenseConfigResponse(active=_out(active, db) if active else None, history=[_out(c, db) for c in hist])


@router.post("/defense/config", response_model=DefenseConfigOut, status_code=201)
def save_config(req: DefenseConfigIn, user: User = Depends(require_roles("blue_team")), db: Session = Depends(get_db)):
    prev = defense_store.get_active(db)
    c = defense_store.save_new_version(db, name=req.name, input_screen=req.input_screen, hardened_prompt=req.hardened_prompt,
                                       output_redaction=req.output_redaction, output_contract=req.output_contract,
                                       policy_text=req.policy_text, user_id=user.id)
    audit.record(db, action="defense.config.update", actor=user.email, outcome="success", details={
        "role": user.role, "config_id": c.id, "previous_config_id": prev.id if prev else None,
        "input_screen": req.input_screen, "hardened_prompt": req.hardened_prompt, "output_redaction": req.output_redaction,
        "output_contract": req.output_contract,
        "policy_text_length": len(req.policy_text)})  # policy text itself is not copied into the log
    return _out(c, db)


def _comparison(db, bg, base, dg, defd, cfg_id) -> ComparisonResponse:
    m = metrics.compare(base, defd)
    return ComparisonResponse(baseline_group_id=bg, defended_group_id=dg, defense_config_id=cfg_id, **m)


@router.post("/comparisons/run", response_model=ComparisonResponse)
def run_comparison(user: User = Depends(require_roles("blue_team")), db: Session = Depends(get_db), factory=Depends(get_provider_factory)):
    _, cfg = defense_store.resolve(db, "defended")  # 409 if nothing saved
    try:
        bg, base, dg, defd = runner.run_comparison(db, factory, user, cfg)
    except runner.BusyError:
        raise BUSY
    except runner.ProviderUnavailable as e:
        raise unavailable(e)
    audit.record(db, action="comparison.run", actor=user.email, outcome="success",
                 details={"role": user.role, "baseline_group": bg, "defended_group": dg, "defense_config_id": cfg.config_id})
    return _comparison(db, bg, base, dg, defd, cfg.config_id)


@router.get("/comparisons/latest", response_model=ComparisonResponse | None)
def latest_comparison(user: User = Depends(require_roles("blue_team", "admin")), db: Session = Depends(get_db)):
    """Re-computes from stored outcomes for the most recent comparison (always a matched baseline+defended pair)."""
    scope = [TestRun.comparison_id.is_not(None)]
    if user.role != "admin":
        scope.append(TestRun.owner_role == user.role)
    newest = db.scalar(select(TestRun).where(*scope).order_by(TestRun.id.desc()).limit(1))
    if not newest:
        return None
    rows = db.scalars(select(TestRun).where(TestRun.comparison_id == newest.comparison_id)).all()
    base = [r for r in rows if r.mode == "baseline"]
    defd = [r for r in rows if r.mode == "defended"]
    if not base or not defd:
        return None
    return _comparison(db, base[0].run_group_id, base, defd[0].run_group_id, defd, defd[0].defense_config_id)
