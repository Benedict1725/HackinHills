from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from ..database import get_db
from ..models import AuditEvent, User
from ..schemas import AuditEventOut, AuditListResponse, VerifyResponse
from ..services import audit
from ..services.auth import require_roles

router = APIRouter(prefix="/api", tags=["audit"])
# Deliberately read-only: there are no endpoints that update or delete audit events.
NOTE = ("A VERIFIED result means no stored event was altered or removed from the middle of the chain. It cannot detect an attacker "
        "who rewrites the entire chain or deletes the newest events; record the head hash somewhere independent to detect that.")


def _out(e: AuditEvent) -> AuditEventOut:
    return AuditEventOut(id=e.id, ts=e.ts, actor=e.actor, action=e.action, test_id=e.test_id, outcome=e.status,
                         details=e.details, prev_hash=e.prev_hash, event_hash=e.event_hash)


@router.get("/audit", response_model=AuditListResponse)
def list_audit(action: str | None = Query(None, max_length=60), limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0),
               user: User = Depends(require_roles("admin")), db: Session = Depends(get_db)):
    q = select(AuditEvent)
    if action:
        q = q.where(AuditEvent.action.startswith(action))
    total = db.scalar(select(func.count()).select_from(q.subquery()))
    rows = db.scalars(q.order_by(AuditEvent.id.desc()).limit(limit).offset(offset)).all()
    return AuditListResponse(items=[_out(r) for r in rows], total=total)


@router.post("/audit/verify", response_model=VerifyResponse)
def verify(user: User = Depends(require_roles("admin")), db: Session = Depends(get_db)):
    v = audit.verify_chain(db)
    audit.record(db, action="audit.verify", actor=user.email, outcome="success" if v.ok else "failure",
                 details={"role": user.role, "events_checked": v.checked, "result": "VERIFIED" if v.ok else "INTEGRITY FAILURE",
                          "first_inconsistency": v.first_inconsistency})
    return VerifyResponse(result="VERIFIED" if v.ok else "INTEGRITY FAILURE", events_checked=v.checked, head_hash=v.head_hash,
                          first_inconsistency=v.first_inconsistency, note=NOTE)
