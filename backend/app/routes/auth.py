from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import delete, select
from sqlalchemy.orm import Session
from ..database import get_db
from ..models import AuthSession, User
from ..schemas import LoginRequest, LoginResponse, UserOut
from ..services import audit
from ..services.auth import _bearer, clear_failures, current_user, note_failure, throttled
from ..services.security import burn_dummy_verify, expiry, hash_token, new_token, verify_password

router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.post("/login", response_model=LoginResponse)
def login(req: LoginRequest, db: Session = Depends(get_db)):
    email = req.email.strip().lower()
    ident = audit.safe_identity(email)
    if throttled(email):
        audit.record(db, action="auth.login", actor=ident, outcome="denied", details={"reason": "too many failed attempts"})
        raise HTTPException(status_code=429, detail="Too many failed sign-in attempts. Try again in 15 minutes.")
    user = db.scalar(select(User).where(User.email == email))
    if user and verify_password(req.password, user.password_hash):
        clear_failures(email)
        token, th = new_token()
        exp = expiry()
        db.execute(delete(AuthSession).where(AuthSession.expires_at < datetime.now(timezone.utc)))  # purge expired sessions
        db.add(AuthSession(token_hash=th, user_id=user.id, expires_at=exp))
        db.commit()
        audit.record(db, action="auth.login", actor=user.email, outcome="success", details={"role": user.role})
        return LoginResponse(token=token, expires_at=exp, user=UserOut(email=user.email, role=user.role))
    if not user:
        burn_dummy_verify(req.password)
    note_failure(email)
    audit.record(db, action="auth.login", actor=ident, outcome="failure", details={"reason": "invalid credentials"})
    raise HTTPException(status_code=401, detail="Invalid email or password.")


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(current_user)):
    return UserOut(email=user.email, role=user.role)


@router.post("/logout", status_code=204)
def logout(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    db.execute(delete(AuthSession).where(AuthSession.token_hash == hash_token(_bearer(request))))
    db.commit()
    audit.record(db, action="auth.logout", actor=user.email, outcome="success", details={"role": user.role})
