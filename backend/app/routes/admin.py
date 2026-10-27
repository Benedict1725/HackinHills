"""Admin-only user management and operational overview. Every route requires the admin role (enforced server-side)."""
import re
from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session
from ..ai.providers import ProviderError
from .ai import get_provider_factory
from ..database import get_db
from ..models import AuditEvent, AuthSession, TestRun, User
from ..services import audit
from ..services.auth import require_roles
from ..services.security import hash_password

router = APIRouter(prefix="/api/admin", tags=["admin"])
ROLES = ("red_team", "blue_team", "admin")
_EMAIL = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,100}\.[^@\s]{2,}$")


class AdminUser(BaseModel):
    id: int
    email: str
    role: str
    is_active: bool
    created_at: datetime | None = None
    active_sessions: int = 0


class UserCreate(BaseModel):
    email: str = Field(max_length=160)
    role: str
    password: str = Field(min_length=12, max_length=128)

    @field_validator("email")
    @classmethod
    def _e(cls, v):
        v = v.strip().lower()
        if not _EMAIL.match(v): raise ValueError("Enter a valid email address.")
        return v

    @field_validator("role")
    @classmethod
    def _r(cls, v):
        if v not in ROLES: raise ValueError("Role must be red_team, blue_team or admin.")
        return v


class UserUpdate(BaseModel):
    role: str | None = None
    is_active: bool | None = None

    @field_validator("role")
    @classmethod
    def _r(cls, v):
        if v is not None and v not in ROLES: raise ValueError("Role must be red_team, blue_team or admin.")
        return v


def _out(db: Session, u: User) -> AdminUser:
    n = db.scalar(select(func.count()).select_from(AuthSession).where(AuthSession.user_id == u.id, AuthSession.expires_at > datetime.now(timezone.utc))) or 0
    return AdminUser(id=u.id, email=u.email, role=u.role, is_active=u.is_active is not False, created_at=u.created_at, active_sessions=n)


def _active_admins(db: Session) -> int:
    return db.scalar(select(func.count()).select_from(User).where(User.role == "admin", User.is_active.isnot(False))) or 0


@router.get("/users")
def list_users(q: str | None = Query(None, max_length=100), role: str | None = None, status: str | None = Query(None, pattern="^(active|inactive)$"),
               admin: User = Depends(require_roles("admin")), db: Session = Depends(get_db)):
    stmt = select(User).order_by(User.id)
    if q: stmt = stmt.where(User.email.ilike(f"%{q.strip()}%"))
    if role in ROLES: stmt = stmt.where(User.role == role)
    if status == "active": stmt = stmt.where(User.is_active.isnot(False))
    if status == "inactive": stmt = stmt.where(User.is_active.is_(False))
    return {"items": [_out(db, u) for u in db.scalars(stmt).all()]}


@router.post("/users", response_model=AdminUser, status_code=201)
def create_user(req: UserCreate, admin: User = Depends(require_roles("admin")), db: Session = Depends(get_db)):
    if db.scalar(select(User).where(User.email == req.email)):
        raise HTTPException(status_code=409, detail="An account with this email already exists.")
    u = User(email=req.email, role=req.role, password_hash=hash_password(req.password), is_active=True)
    db.add(u); db.commit(); db.refresh(u)
    audit.record(db, action="admin.user.create", actor=admin.email, outcome="success", details={"role": admin.role, "target": u.email, "new_role": u.role})  # never the password
    return _out(db, u)


@router.patch("/users/{user_id}", response_model=AdminUser)
def update_user(user_id: int, req: UserUpdate, admin: User = Depends(require_roles("admin")), db: Session = Depends(get_db)):
    u = db.get(User, user_id)
    if not u: raise HTTPException(status_code=404, detail="User not found.")
    if req.role is None and req.is_active is None: raise HTTPException(status_code=422, detail="Nothing to change.")
    losing_admin = u.role == "admin" and ((req.role and req.role != "admin") or req.is_active is False)
    if losing_admin and u.is_active is not False:
        if u.id == admin.id:
            raise HTTPException(status_code=409, detail="You cannot demote or deactivate your own account. Ask another administrator.")
        if _active_admins(db) <= 1:
            raise HTTPException(status_code=409, detail="This is the last active administrator and cannot be demoted or deactivated.")
    if u.id == admin.id and req.is_active is False:
        raise HTTPException(status_code=409, detail="You cannot deactivate your own account.")
    changes = {}
    if req.role is not None and req.role != u.role: changes["role"] = [u.role, req.role]; u.role = req.role
    if req.is_active is not None and (u.is_active is not False) != req.is_active: changes["is_active"] = [u.is_active is not False, req.is_active]; u.is_active = req.is_active
    revoked = False
    if changes and (u.is_active is False or "role" in changes):
        db.execute(delete(AuthSession).where(AuthSession.user_id == u.id)); revoked = True   # force re-authentication with the new access level
    db.commit(); db.refresh(u)
    if changes:
        audit.record(db, action="admin.user.update", actor=admin.email, outcome="success", details={"role": admin.role, "target": u.email, "changes": changes, "sessions_revoked": revoked})
    return _out(db, u)


@router.get("/overview")
def overview(factory=Depends(get_provider_factory), admin: User = Depends(require_roles("admin")), db: Session = Depends(get_db)):
    users = db.scalars(select(User)).all()
    by_role = {r: sum(1 for u in users if u.role == r and u.is_active is not False) for r in ROLES}
    since = datetime.now(timezone.utc) - timedelta(days=7)
    tests7 = db.scalar(select(func.count()).select_from(TestRun).where(TestRun.created_at >= since)) or 0
    errors7 = db.scalar(select(func.count()).select_from(TestRun).where(TestRun.created_at >= since, TestRun.execution_status == "ERROR")) or 0
    denied7 = db.scalar(select(func.count()).select_from(AuditEvent).where(AuditEvent.created_at >= since, AuditEvent.status == "denied")) or 0
    failed_logins7 = db.scalar(select(func.count()).select_from(AuditEvent).where(AuditEvent.created_at >= since, AuditEvent.action == "auth.login", AuditEvent.status == "failure")) or 0
    try:
        h = factory().health(); ai = {"ok": h.ok, "provider": h.provider, "model": h.model or None, "detail": h.detail}
    except ProviderError as e:
        ai = {"ok": False, "provider": None, "model": None, "detail": e.message}
    alerts = []
    if not ai["ok"]: alerts.append({"level": "error", "text": f"The AI model is not reachable: {ai['detail']}"})
    if errors7: alerts.append({"level": "warn", "text": f"{errors7} test run(s) failed to execute in the last 7 days (model or provider errors)."})
    if denied7: alerts.append({"level": "warn", "text": f"{denied7} access attempt(s) were denied in the last 7 days. Review the Security Activity tab."})
    if failed_logins7 >= 5: alerts.append({"level": "warn", "text": f"{failed_logins7} failed sign-ins in the last 7 days."})
    recent = db.scalars(select(TestRun).where(TestRun.test_id.isnot(None)).order_by(TestRun.id.desc()).limit(8)).all()
    return {"users": {"total": len(users), "active": sum(1 for u in users if u.is_active is not False), "by_role": by_role},
            "tests_last_7_days": tests7, "execution_errors_last_7_days": errors7, "denied_last_7_days": denied7,
            "database": "ok", "ai": ai, "alerts": alerts,
            "recent_tests": [{"test_id": r.test_id, "category": r.category, "execution_status": r.execution_status, "security_verdict": r.security_verdict,
                              "severity": r.severity, "mode": r.mode, "owner_role": r.owner_role, "created_at": r.created_at} for r in recent]}
