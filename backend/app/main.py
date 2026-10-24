import logging
import os
from contextlib import asynccontextmanager
from dotenv import load_dotenv
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import func, select
from .database import DATABASE_URL, SessionLocal, init_db
from .models import User
from .routes import ai, audit, auth, dashboard, defense, health, reports, tests

load_dotenv()
logging.basicConfig(level=logging.INFO)


log = logging.getLogger("leakproof")


def warn_if_no_users(session_factory) -> bool:
    """Without users nobody can sign in; say so at startup instead of failing silently in the UI."""
    with session_factory() as db:
        if db.scalar(select(func.count()).select_from(User)):
            return True
    log.warning("No users exist, so nobody can sign in. Create demo users with: python -m scripts.seed_demo_users")
    return False


@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        init_db()
    except Exception as e:
        log.error("Database initialisation failed (%s: %s). Check DATABASE_URL and that the file/folder is writable: %s",
                  type(e).__name__, e, DATABASE_URL)
        raise
    log.info("Database: %s", DATABASE_URL)
    warn_if_no_users(SessionLocal)
    yield


app = FastAPI(title="LeakProof AI API", version="0.3.0", lifespan=lifespan)


@app.middleware("http")
async def catch_unhandled(request: Request, call_next):
    """Registered BEFORE CORS so it sits inside it: generic 500s still carry CORS headers
    (otherwise the browser reports a misleading CORS error instead of the real status)."""
    try:
        return await call_next(request)
    except Exception as exc:
        logging.getLogger("leakproof").error("Unhandled %s on %s", type(exc).__name__, request.url.path)
        return JSONResponse(status_code=500, content={"detail": "Internal server error."})


origins = [o.strip() for o in os.getenv("CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173").split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    # Vite moves to 5174, 5175... when 5173 is busy; allow any local dev port, nothing else.
    allow_origin_regex=r"^https?://(localhost|127\.0\.0\.1)(:\d+)?$",
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)

for r in (health, auth, ai, dashboard, defense, tests, audit, reports):
    app.include_router(r.router)
