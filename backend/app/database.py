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
    backfill_severity()


_NEW_COLUMNS = {
    "test_runs": {
        "test_id": "VARCHAR(32)", "test_case_id": "VARCHAR(32)", "test_name": "VARCHAR(200)",
        "provider": "VARCHAR(32)", "explanation": "TEXT", "duration_ms": "INTEGER",
        "owner_role": "VARCHAR(16)", "run_group_id": "VARCHAR(32)", "comparison_id": "VARCHAR(32)",
        "defense_triggered": "BOOLEAN DEFAULT 0", "defense_actions": "TEXT",
        "test_suite_version": "VARCHAR(32)", "trial_number": "INTEGER DEFAULT 1", "model_digest": "VARCHAR(255)",
        "human_review_status": "VARCHAR(16)", "parent_test_id": "VARCHAR(32)",
        "execution_status": "VARCHAR(16)", "severity": "VARCHAR(16)", "security_verdict": "VARCHAR(16)", "test_objective": "TEXT", "error_message": "TEXT",
    },
    "defense_configs": {
        "hardened_prompt": "BOOLEAN DEFAULT 1", "is_active": "BOOLEAN DEFAULT 0",
        # Existing saved configurations retain secure, backwards-compatible behavior.
        "output_contract": "BOOLEAN DEFAULT 1",
    },
    "users": {"is_active": "BOOLEAN DEFAULT 1"},
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
        if insp.has_table("test_runs"):
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_test_runs_parent_test_id ON test_runs (parent_test_id)"))
            # Backfill rows written before execution status and security verdict were separated. Idempotent; never overwrites.
            # Skipped for ancient schemas that have no `outcome` column to derive from.
            has_outcome = "outcome" in {c["name"] for c in inspect(conn).get_columns("test_runs")}
            if has_outcome:
                conn.execute(text("UPDATE test_runs SET execution_status = CASE WHEN outcome = 'ERROR' THEN 'ERROR' ELSE 'COMPLETED' END "
                                  "WHERE execution_status IS NULL"))
                conn.execute(text("UPDATE test_runs SET security_verdict = outcome WHERE security_verdict IS NULL AND outcome <> 'ERROR'"))
                conn.execute(text("UPDATE test_runs SET error_message = explanation WHERE error_message IS NULL AND outcome = 'ERROR'"))


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def backfill_severity() -> int:
    """Give rows written before severity existed a value derived from their stored verdict. Idempotent: only rows whose
    severity is NULL are touched, execution-ERROR rows stay NULL, and no other column is modified. Reads only the columns
    it needs, so it also works on older schemas."""
    from .services import evaluator
    from .services.testcases import CASES, custom_spec
    insp = inspect(engine)
    if not insp.has_table("test_runs"):
        return 0
    have = {c["name"] for c in insp.get_columns("test_runs")}
    if "severity" not in have or "outcome" not in have:
        return 0
    want = [c for c in ("id", "category", "test_case_id", "test_objective", "outcome", "execution_status", "security_verdict") if c in have]
    n = 0
    with engine.begin() as conn:
        for row in conn.execute(text(f"SELECT {', '.join(want)} FROM test_runs WHERE severity IS NULL")).mappings().all():
            if (row.get("execution_status") or ("ERROR" if row["outcome"] == "ERROR" else "COMPLETED")) == "ERROR":
                continue
            verdict = row.get("security_verdict") or (row["outcome"] if row["outcome"] != "ERROR" else None)
            case = CASES.get(row.get("test_case_id")) if row.get("test_case_id") else None
            check = case.check if case else custom_spec(row["category"], row.get("test_objective"))[1]
            sev = evaluator.severity_for(verdict, check, case.severity if case else None)
            if sev:
                conn.execute(text("UPDATE test_runs SET severity = :s WHERE id = :i"), {"s": sev, "i": row["id"]})
                n += 1
    return n
