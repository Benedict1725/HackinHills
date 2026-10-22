"""Regression tests for defects found during the stabilisation pass."""
import logging
import pytest
from sqlalchemy import select
from sqlalchemy.exc import OperationalError
from app.models import AuditEvent, AuthSession
from app.services import audit
from tests.conftest import PASSWORD, FakeProvider, audit_rows
from tests.test_metrics import model


def test_relative_sqlite_url_is_anchored_to_backend_dir_not_cwd(tmp_path):
    from app.database import resolve_database_url
    assert resolve_database_url("sqlite:///./leakproof.db", base=tmp_path) == f"sqlite:///{(tmp_path / 'leakproof.db').as_posix()}"
    assert resolve_database_url("sqlite:////abs/x.db", base=tmp_path) == "sqlite:////abs/x.db"      # absolute untouched
    assert resolve_database_url("sqlite://", base=tmp_path) == "sqlite://"                          # in-memory untouched
    assert resolve_database_url("postgresql://u@h/db", base=tmp_path) == "postgresql://u@h/db"


def test_latest_comparison_is_always_a_matched_pair(env):
    c, h, *_ = env
    b = h["hdr"]["blue_team"]
    h["provider"] = FakeProvider(model)
    c.post("/api/defense/config", json={}, headers=b)
    first = c.post("/api/comparisons/run", headers=b).json()
    c.post("/api/tests/run-suite", json={"mode": "baseline"}, headers=b)   # an unrelated later baseline run
    again = c.get("/api/comparisons/latest", headers=b).json()
    assert (again["baseline_group_id"], again["defended_group_id"]) == (first["baseline_group_id"], first["defended_group_id"])


def test_failed_audit_commit_is_rolled_back_and_does_not_poison_the_session(env):
    _, _, Session, _ = env
    with Session() as db:
        real_commit, state = db.commit, {"n": 0}
        def flaky():
            state["n"] += 1
            if state["n"] == 1:
                raise OperationalError("COMMIT", {}, Exception("disk I/O error"))
            return real_commit()
        db.commit = flaky
        with pytest.raises(OperationalError):
            audit.record(db, action="will.fail", actor="svc", outcome="success")
        audit.record(db, action="after.failure", actor="svc", outcome="success")
    ev = audit_rows(Session)
    assert [e.action for e in ev] == ["after.failure"]           # the failed event must not survive
    with Session() as db:
        assert audit.verify_chain(db).ok


def test_expired_sessions_are_purged_on_login(env):
    from datetime import datetime, timedelta, timezone
    c, h, Session, _ = env
    with Session() as db:
        db.add(AuthSession(token_hash="e" * 64, user_id=1, expires_at=datetime.now(timezone.utc) - timedelta(hours=1))); db.commit()
    c.post("/api/auth/login", json={"email": "red_team@test.local", "password": PASSWORD}, headers={"Authorization": ""})
    with Session() as db:
        assert db.scalar(select(AuthSession).where(AuthSession.token_hash == "e" * 64)) is None


def test_login_reports_the_same_expiry_that_is_stored(env):
    c, h, Session, _ = env
    r = c.post("/api/auth/login", json={"email": "red_team@test.local", "password": PASSWORD}, headers={"Authorization": ""}).json()
    from app.services.security import hash_token
    from datetime import datetime
    with Session() as db:
        s = db.scalar(select(AuthSession).where(AuthSession.token_hash == hash_token(r["token"])))
        assert datetime.fromisoformat(r["expires_at"]).replace(tzinfo=None) == s.expires_at.replace(tzinfo=None)


def test_startup_warns_when_no_users_exist(env, caplog):
    from app.main import warn_if_no_users
    _, _, Session, _ = env
    with Session() as db:
        db.execute(AuthSession.__table__.delete())
        from app.models import User
        db.execute(User.__table__.delete()); db.commit()
    with caplog.at_level(logging.WARNING, logger="leakproof"):
        assert warn_if_no_users(Session) is False
    assert "seed_demo_users" in caplog.text


def test_server_error_in_one_request_does_not_break_the_next(env, monkeypatch):
    c, h, *_ = env
    from app.services import runner
    monkeypatch.setattr(runner.audit, "record", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    assert c.post("/api/tests/run", json={"test_case_id": "nr-001"}).status_code == 500
    monkeypatch.undo()
    assert c.post("/api/tests/run", json={"test_case_id": "nr-001"}).status_code == 201
