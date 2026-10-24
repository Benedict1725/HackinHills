import os
from pathlib import Path
from dotenv import load_dotenv
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import declarative_base, sessionmaker

load_dotenv()
BACKEND_DIR = Path(__file__).resolve().parent.parent


def resolve_database_url(url: str, base: Path = BACKEND_DIR) -> str:
    """A relative SQLite path would otherwise resolve against the *current directory*, so starting the
    backend from another folder silently created a second, empty database. Anchor it to backend/ instead."""
    prefix = "sqlite:///"
    if not url.startswith(prefix) or url.startswith(prefix + "/"):
        return url                      # not SQLite, in-memory (sqlite://), or Unix-absolute (sqlite:////...)
    path = url[len(prefix):]
    if not path or path.startswith(":memory:") or Path(path).is_absolute():
        return url                      # in-memory or Windows-absolute (sqlite:///C:/...)
    return prefix + (base / path).as_posix()


DATABASE_URL = resolve_database_url(os.getenv("DATABASE_URL", "sqlite:///./leakproof.db"))

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {},
)
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
Base = declarative_base()


def init_db() -> None:
    from . import models  # noqa: F401  (imported to register the tables)
    Base.metadata.create_all(bind=engine)
    migrate_day1_schema()


_NEW_COLUMNS = {
    "test_runs": {
        "test_id": "VARCHAR(32)", "test_case_id": "VARCHAR(32)", "test_name": "VARCHAR(200)",
        "provider": "VARCHAR(32)", "explanation": "TEXT", "duration_ms": "INTEGER",
        "owner_role": "VARCHAR(16)", "run_group_id": "VARCHAR(32)", "comparison_id": "VARCHAR(32)",
        "defense_triggered": "BOOLEAN DEFAULT 0", "defense_actions": "TEXT",
        "test_suite_version": "VARCHAR(32)", "trial_number": "INTEGER DEFAULT 1", "model_digest": "VARCHAR(255)",
        "human_review_status": "VARCHAR(16)",
    },
    "defense_configs": {
        "hardened_prompt": "BOOLEAN DEFAULT 1", "is_active": "BOOLEAN DEFAULT 0",
        # Existing saved configurations retain secure, backwards-compatible behavior.
        "output_contract": "BOOLEAN DEFAULT 1",
    },
    "audit_events": {"ts": "VARCHAR(40)", "test_id": "VARCHAR(32)", "prev_hash": "VARCHAR(64)", "event_hash": "VARCHAR(64)"},
}


def migrate_day1_schema() -> None:
    """Add columns introduced after Day 1 to existing tables (create_all never alters tables).
    Only adds; never drops or rewrites data."""
    insp = inspect(engine)
    with engine.begin() as conn:
        for table, cols in _NEW_COLUMNS.items():
            if not insp.has_table(table):
                continue
            existing = {c["name"] for c in insp.get_columns(table)}
            for name, ddl in cols.items():
                if name not in existing:
                    conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}"))
        conn.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS ix_test_runs_test_id ON test_runs (test_id)"))


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
