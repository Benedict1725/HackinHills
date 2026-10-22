"""Authentication and role-based authorization dependencies. The role always comes from the database."""
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from fastapi import Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session
from ..database import get_db
from ..models import AuthSession, User
from . import audit
from .security import hash_token


def _bearer(request: Request) -> str | None:
    h = request.headers.get("authorization", "")
    return h[7:].strip() if h.lower().startswith("bearer ") and len(h) > 7 else None


def current_user(request: Request, db: Session = Depends(get_db)) -> User:
    token = _bearer(request)
    if not token:
        raise HTTPException(status_code=401, detail="Authentication required.", headers={"WWW-Authenticate": "Bearer"})
    s = db.scalar(select(AuthSession).where(AuthSession.token_hash == hash_token(token)))
    exp = s.expires_at.replace(tzinfo=timezone.utc) if s and s.expires_at.tzinfo is None else (s.expires_at if s else None)
    if not s or exp <= datetime.now(timezone.utc):
        raise HTTPException(status_code=401, detail="Session is invalid or expired. Please sign in again.", headers={"WWW-Authenticate": "Bearer"})
    user = db.get(User, s.user_id)
    if not user:
        raise HTTPException(status_code=401, detail="Session is invalid.")
    return user


def require_roles(*roles: str):
    """Dependency factory. Denials are written to the audit log before the 403 is returned."""
    def dep(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)) -> User:
        if user.role not in roles:
            audit.record(db, action="authz.denied", actor=user.email, outcome="denied",
                         details={"role": user.role, "method": request.method, "path": request.url.path, "required": list(roles)})
            raise HTTPException(status_code=403, detail="Your role is not permitted to perform this action.")
        return user
    return dep


def deny_record_access(db: Session, user: User, what: str, ref: str) -> None:
    audit.record(db, action="authz.denied", actor=user.email, outcome="denied",
                 test_id=ref if what == "test" else None,
                 details={"role": user.role, "resource": what, "reason": "cross-team record access"})
    raise HTTPException(status_code=403, detail="You do not have access to this record.")


# Login throttle: 5 failures per email per 15 minutes (in-memory, single process).
_fails: dict[str, deque] = defaultdict(deque)
WINDOW, MAX_FAILS = 900, 5


def throttled(key: str) -> bool:
    q, now = _fails[key], time.time()
    while q and now - q[0] > WINDOW:
        q.popleft()
    return len(q) >= MAX_FAILS


def note_failure(key: str) -> None:
    _fails[key].append(time.time())


def clear_failures(key: str) -> None:
    _fails.pop(key, None)
