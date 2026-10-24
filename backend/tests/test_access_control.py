import pytest
from datetime import datetime, timedelta, timezone
from sqlalchemy import select, text
from app.models import AuthSession, TestRun
from app.services.security import hash_password, hash_token, verify_password
from tests.conftest import PASSWORD, FakeProvider, audit_rows


def H(h, role): return h["hdr"][role]


def test_public_health_needs_no_login(env):
    c, *_ = env
    assert c.get("/api/health", headers={"Authorization": ""}).status_code == 200


@pytest.mark.parametrize("method,path", [
    ("GET", "/api/tests"), ("GET", "/api/tests/LP-X"), ("GET", "/api/test-cases"), ("GET", "/api/dashboard"), ("GET", "/api/ai/health"),
    ("POST", "/api/tests/run"), ("POST", "/api/tests/run-suite"), ("GET", "/api/defense/config"), ("POST", "/api/defense/config"),
    ("POST", "/api/comparisons/run"), ("GET", "/api/comparisons/latest"), ("GET", "/api/audit"), ("POST", "/api/audit/verify"), ("GET", "/api/auth/me"),
])
def test_every_protected_endpoint_requires_authentication(env, method, path):
    c, *_ = env
    r = c.request(method, path, headers={"Authorization": ""}, json={} if method == "POST" else None)
    assert r.status_code == 401, (path, r.status_code)


def test_garbage_and_expired_tokens_are_401(env):
    c, h, Session, _ = env
    assert c.get("/api/tests", headers={"Authorization": "Bearer nonsense"}).status_code == 401
    assert c.get("/api/tests", headers={"Authorization": "Basic abc"}).status_code == 401
    tok = H(h, "blue_team")["Authorization"][7:]
    with Session() as db:
        s = db.scalar(select(AuthSession).where(AuthSession.token_hash == hash_token(tok)))
        s.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1); db.commit()
    assert c.get("/api/tests", headers=H(h, "blue_team")).status_code == 401


# ---- login
def test_login_success_returns_role_from_database_and_is_audited(env):
    c, h, Session, _ = env
    r = c.post("/api/auth/login", json={"email": "BLUE_TEAM@test.local", "password": PASSWORD, "role": "admin"}, headers={"Authorization": ""})
    assert r.status_code == 200 and r.json()["user"]["role"] == "blue_team"   # client-supplied role ignored
    tok = r.json()["token"]
    assert c.get("/api/auth/me", headers={"Authorization": f"Bearer {tok}"}).json()["role"] == "blue_team"
    with Session() as db:  # only the hash of the token is stored
        assert db.scalar(select(AuthSession).where(AuthSession.token_hash == tok)) is None
        assert db.scalar(select(AuthSession).where(AuthSession.token_hash == hash_token(tok))) is not None
    assert any(e.action == "auth.login" and e.status == "success" for e in audit_rows(Session))


def test_login_failures_are_uniform_and_audited(env):
    c, h, Session, _ = env
    a = c.post("/api/auth/login", json={"email": "blue_team@test.local", "password": "wrong"}, headers={"Authorization": ""})
    b = c.post("/api/auth/login", json={"email": "nobody@test.local", "password": "wrong"}, headers={"Authorization": ""})
    assert a.status_code == b.status_code == 401 and a.json() == b.json()
    assert [e.status for e in audit_rows(Session) if e.action == "auth.login"] == ["failure", "failure"]


def test_login_throttle(env):
    c, *_ = env
    for _ in range(5):
        c.post("/api/auth/login", json={"email": "red_team@test.local", "password": "bad"}, headers={"Authorization": ""})
    r = c.post("/api/auth/login", json={"email": "red_team@test.local", "password": PASSWORD}, headers={"Authorization": ""})
    assert r.status_code == 429


def test_password_typed_into_email_field_is_not_logged(env):
    c, h, Session, _ = env
    c.post("/api/auth/login", json={"email": "my-secret-password-123", "password": "x"}, headers={"Authorization": ""})
    assert "my-secret-password-123" not in str([(e.actor, e.details) for e in audit_rows(Session)])


def test_password_hashing_is_salted_and_not_plaintext():
    a, b = hash_password("pw-12345678"), hash_password("pw-12345678")
    assert a != b and "pw-12345678" not in a and verify_password("pw-12345678", a) and not verify_password("nope", a)
    assert not verify_password("x", "garbage")


def test_logout_invalidates_session(env):
    c, h, *_ = env
    assert c.post("/api/auth/logout", headers=H(h, "blue_team")).status_code == 204
    assert c.get("/api/tests", headers=H(h, "blue_team")).status_code == 401


# ---- role permissions
def test_cannot_forge_role_via_headers_or_query(env):
    c, h, *_ = env
    r = c.get("/api/audit?role=admin", headers={**H(h, "red_team"), "X-Role": "admin", "X-User-Role": "admin"})
    assert r.status_code == 403


@pytest.mark.parametrize("role,method,path,body", [
    ("red_team", "GET", "/api/defense/config", None),
    ("red_team", "POST", "/api/defense/config", {"input_screen": False}),
    ("red_team", "POST", "/api/comparisons/run", None),
    ("red_team", "GET", "/api/comparisons/latest", None),
    ("red_team", "GET", "/api/audit", None),
    ("red_team", "POST", "/api/audit/verify", None),
    ("blue_team", "POST", "/api/tests/run", {"test_case_id": "nr-001"}),
    ("blue_team", "POST", "/api/tests/run", {"prompt": "custom attack", "category": "jailbreak"}),
    ("blue_team", "GET", "/api/audit", None),
    ("blue_team", "POST", "/api/audit/verify", None),
    ("admin", "POST", "/api/defense/config", {}),
    ("admin", "POST", "/api/tests/run", {"test_case_id": "nr-001"}),
    ("admin", "POST", "/api/tests/run-suite", None),
    ("admin", "POST", "/api/comparisons/run", None),
])
def test_forbidden_actions_return_403_and_are_audited(env, role, method, path, body):
    c, h, Session, _ = env
    r = c.request(method, path, headers=H(h, role), json=body)
    assert r.status_code == 403, r.text
    ev = [e for e in audit_rows(Session) if e.action == "authz.denied"]
    assert len(ev) == 1 and ev[0].actor == f"{role}@test.local" and ev[0].status == "denied"
    assert ev[0].details["path"] == path and ev[0].details["role"] == role


def test_allowed_actions_work_for_each_role(env):
    c, h, *_ = env
    assert c.get("/api/defense/config", headers=H(h, "blue_team")).status_code == 200
    assert c.get("/api/defense/config", headers=H(h, "admin")).status_code == 200       # read-only oversight
    assert c.post("/api/defense/config", json={}, headers=H(h, "blue_team")).status_code == 201
    assert c.post("/api/tests/run", json={"test_case_id": "nr-001"}, headers=H(h, "red_team")).status_code == 201
    assert c.post("/api/tests/run-suite", headers=H(h, "blue_team")).status_code == 200
    assert c.get("/api/audit", headers=H(h, "admin")).status_code == 200
    assert c.post("/api/audit/verify", headers=H(h, "admin")).status_code == 200


# ---- record-level ownership
def test_cross_team_record_access_denied_and_recorded(env):
    c, h, Session, _ = env
    h["provider"] = FakeProvider("ok")
    tid = c.post("/api/tests/run", json={"prompt": "red team private attack text", "category": "jailbreak"}).json()["test_id"]
    r = c.get(f"/api/tests/{tid}", headers=H(h, "blue_team"))
    assert r.status_code == 403 and "private attack text" not in r.text
    ev = [e for e in audit_rows(Session) if e.action == "authz.denied"]
    assert len(ev) == 1 and ev[0].test_id == tid and ev[0].actor == "blue_team@test.local"
    assert c.get(f"/api/tests/{tid}", headers=H(h, "red_team")).status_code == 200
    assert c.get(f"/api/tests/{tid}", headers=H(h, "admin")).status_code == 200


def test_blue_cannot_see_red_artifacts_in_lists_or_dashboard_and_vice_versa(env):
    c, h, *_ = env
    h["provider"] = FakeProvider("ok")
    red_id = c.post("/api/tests/run", json={"test_case_id": "nr-001"}).json()["test_id"]
    blue_run = c.post("/api/tests/run-suite", headers=H(h, "blue_team")).json()
    blue_id = blue_run["results"][0]["test_id"]
    red_list = c.get("/api/tests", headers=H(h, "red_team")).json()
    blue_list = c.get("/api/tests", headers=H(h, "blue_team")).json()
    assert [t["test_id"] for t in red_list["items"]] == [red_id]
    assert red_id not in [t["test_id"] for t in blue_list["items"]] and blue_list["total"] == 14
    assert c.get(f"/api/tests/{blue_id}", headers=H(h, "red_team")).status_code == 403
    assert c.get("/api/dashboard", headers=H(h, "red_team")).json()["total_tests"] == 1
    assert c.get("/api/dashboard", headers=H(h, "blue_team")).json()["total_tests"] == 14
    assert c.get("/api/dashboard", headers=H(h, "admin")).json()["total_tests"] == 15


def test_red_team_cannot_see_private_defense_details(env):
    c, h, *_ = env
    c.post("/api/defense/config", json={}, headers=H(h, "blue_team"))
    h["provider"] = FakeProvider("ok")
    d = c.post("/api/tests/run", json={"test_case_id": "jb-001"}).json()
    assert d["defense_triggered"] is True and d["defense_actions"] is None and d["defense_config_id"] is None
    b = c.post("/api/tests/run-suite", headers=H(h, "blue_team")).json()["results"][0]
    assert b["defense_actions"] is not None and b["defense_config_id"] is not None


def test_legacy_rows_without_owner_are_admin_only(env):
    c, h, Session, _ = env
    with Session() as db:
        db.add(TestRun(test_id="LP-LEGACY-1", category="jailbreak", prompt="old", outcome="PASS", owner_role=None)); db.commit()
    assert c.get("/api/tests/LP-LEGACY-1", headers=H(h, "admin")).status_code == 200
    for role in ("red_team", "blue_team"):
        assert c.get("/api/tests/LP-LEGACY-1", headers=H(h, role)).status_code == 403


def test_unknown_id_is_404_not_403(env):
    c, *_ = env
    assert c.get("/api/tests/LP-NOPE").status_code == 404


def test_run_by_red_team_is_attributed_to_red_team(env):
    c, h, Session, _ = env
    c.post("/api/tests/run", json={"test_case_id": "nr-001"})
    with Session() as db:
        r = db.scalar(select(TestRun))
        assert r.owner_role == "red_team" and r.user_id is not None
