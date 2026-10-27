"""Create demo accounts (one per role). Safe to re-run: existing users are left unchanged.

    python -m scripts.seed_demo_users                       # random passwords, printed once
    LEAKPROOF_DEMO_PASSWORD='choose-a-password' python -m scripts.seed_demo_users

Demo accounts are for local hackathon use only. Do not use them on a shared or public deployment."""
import os
import secrets
from sqlalchemy import select
from app.database import SessionLocal, init_db
from app.models import User
from app.services.security import hash_password

ACCOUNTS = [("red@leakproof.local", "red_team"), ("blue@leakproof.local", "blue_team"), ("admin@leakproof.local", "admin")]

init_db()
shared = os.getenv("LEAKPROOF_DEMO_PASSWORD")
if shared and len(shared) < 8:
    raise SystemExit("LEAKPROOF_DEMO_PASSWORD must be at least 8 characters.")
with SessionLocal() as db:
    for email, role in ACCOUNTS:
        if db.scalar(select(User).where(User.email == email)):
            print(f"{email:24} exists (unchanged)")
            continue
        pw = shared or secrets.token_urlsafe(9)
        db.add(User(email=email, role=role, password_hash=hash_password(pw)))
        db.commit()
        print(f"{email:24} {role:10} password: {pw}")
