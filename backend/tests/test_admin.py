"""Admin user management, role enforcement on the backend, last-admin / self-lockout guards, presets."""
from sqlalchemy import select
from app.models import AuditEvent, User
from app.services.defenses import PRESETS

A = "/api/admin"


def hdr(h, role): return h["hdr"][role]


def user_id(Session, email):
    with Session() as db:
        return db.scalar(select(User.id).where(User.email == email))


def test_every_admin_route_is_admin_only(env):
    c, h, *_ = env
    for role in ("red_team", "blue_team"):
        assert c.get(f"{A}/users", headers=hdr(h, role)).status_code == 403
        assert c.get(f"{A}/overview", headers=hdr(h, role)).status_code == 403
        assert c.post(f"{A}/users", headers=hdr(h, role), json={"email": "x@y.zz", "role": "admin", "password": "long-enough-pass"}).status_code == 403
        assert c.patch(f"{A}/users/1", headers=hdr(h, role), json={"role": "admin"}).status_code == 403   # no self-promotion
    assert c.get(f"{A}/users", headers={"Authorization": "Bearer not-a-real-token"}).status_code == 401


def test_create_search_filter_users_and_password_never_returned_or_logged(env):
    c, h, Session, _ = env
    r = c.post(f"{A}/users", headers=hdr(h, "admin"), json={"email": "New.Person@Example.com", "role": "blue_team", "password": "a-very-long-password"})
    assert r.status_code == 201 and r.json()["email"] == "new.person@example.com" and "password" not in r.text
    assert c.post(f"{A}/users", headers=hdr(h, "admin"), json={"email": "new.person@example.com", "role": "red_team", "password": "a-very-long-password"}).status_code == 409
    assert c.post(f"{A}/users", headers=hdr(h, "admin"), json={"email": "short@example.com", "role": "red_team", "password": "short"}).status_code == 422
    assert c.post(f"{A}/users", headers=hdr(h, "admin"), json={"email": "x@example.com", "role": "root", "password": "a-very-long-password"}).status_code == 422
    items = c.get(f"{A}/users", params={"q": "new.person"}, headers=hdr(h, "admin")).json()["items"]
    assert [i["email"] for i in items] == ["new.person@example.com"]
    assert all(i["role"] == "blue_team" for i in c.get(f"{A}/users", params={"role": "blue_team"}, headers=hdr(h, "admin")).json()["items"])
    with Session() as db:
        assert "a-very-long-password" not in "".join(str(e.details) for e in db.scalars(select(AuditEvent)).all())


def test_deactivated_user_cannot_use_session_or_sign_in_and_can_be_reactivated(env):
    c, h, Session, _ = env
    with Session() as db:
        blue = db.scalars(select(User).where(User.role == "blue_team")).first(); uid, email = blue.id, blue.email
    assert c.get("/api/auth/me", headers=hdr(h, "blue_team")).status_code == 200
    r = c.patch(f"{A}/users/{uid}", headers=hdr(h, "admin"), json={"is_active": False})
    assert r.status_code == 200 and r.json()["is_active"] is False
    assert c.get("/api/auth/me", headers=hdr(h, "blue_team")).status_code == 401           # existing session revoked
    assert c.post("/api/auth/login", json={"email": email, "password": "correct-horse-battery"}).status_code == 403
    assert c.patch(f"{A}/users/{uid}", headers=hdr(h, "admin"), json={"is_active": True}).json()["is_active"] is True
    assert c.post("/api/auth/login", json={"email": email, "password": "correct-horse-battery"}).status_code == 200


def test_role_change_revokes_sessions_and_is_audited(env):
    c, h, Session, _ = env
    with Session() as db:
        red = db.scalars(select(User).where(User.role == "red_team")).first(); uid = red.id
    assert c.patch(f"{A}/users/{uid}", headers=hdr(h, "admin"), json={"role": "blue_team"}).json()["role"] == "blue_team"
    assert c.get("/api/auth/me", headers=hdr(h, "red_team")).status_code == 401
    with Session() as db:
        assert any(e.action == "admin.user.update" and e.details["changes"]["role"] == ["red_team", "blue_team"] for e in db.scalars(select(AuditEvent)).all())


def test_admin_cannot_lock_themselves_out_or_remove_last_admin(env):
    c, h, Session, _ = env
    with Session() as db:
        me = db.scalars(select(User).where(User.role == "admin")).first().id
    assert c.patch(f"{A}/users/{me}", headers=hdr(h, "admin"), json={"is_active": False}).status_code == 409
    assert c.patch(f"{A}/users/{me}", headers=hdr(h, "admin"), json={"role": "red_team"}).status_code == 409
    # a second admin may demote the first, but never the last remaining one
    c.post(f"{A}/users", headers=hdr(h, "admin"), json={"email": "second@example.com", "role": "admin", "password": "a-very-long-password"})
    tok = c.post("/api/auth/login", json={"email": "second@example.com", "password": "a-very-long-password"}).json()["token"]
    second = {"Authorization": f"Bearer {tok}"}
    assert c.patch(f"{A}/users/{me}", headers=second, json={"role": "blue_team"}).status_code == 200
    sid = user_id(Session, "second@example.com")
    assert c.patch(f"{A}/users/{sid}", headers=second, json={"is_active": False}).status_code == 409
    assert c.patch(f"{A}/users/9999", headers=second, json={"is_active": False}).status_code == 404
    assert c.patch(f"{A}/users/{sid}", headers=second, json={}).status_code == 422


def test_overview_reports_real_counts_and_model_problems(env):
    c, h, *_ = env
    o = c.get(f"{A}/overview", headers=hdr(h, "admin")).json()
    assert o["users"]["by_role"]["admin"] >= 1 and o["database"] == "ok" and o["ai"]["ok"] is True and o["alerts"] == []
    h["provider"].healthy = False
    o = c.get(f"{A}/overview", headers=hdr(h, "admin")).json()
    assert o["ai"]["ok"] is False and any("not reachable" in a["text"] for a in o["alerts"])


def test_presets_are_documented_nested_and_apply_for_real(env):
    c, h, *_ = env
    p = c.get("/api/defense/presets", headers=hdr(h, "blue_team")).json()
    assert p["default"] == "recommended" and [x["id"] for x in p["presets"]] == ["basic", "recommended", "strict"]
    on = lambda k: {m for m in ("input_screen", "hardened_prompt", "output_redaction", "output_contract") if PRESETS[k][m]}
    assert on("basic") < on("recommended") < on("strict")                                 # strictly nested, so levels genuinely differ
    for x in p["presets"]:
        saved = c.post("/api/defense/config", headers=hdr(h, "blue_team"), json={"name": f"{x['label']} preset", **{m: x[m] for m in ("input_screen", "hardened_prompt", "output_redaction", "output_contract")}, "policy_text": ""})
        assert saved.status_code == 201 and all(saved.json()[m] == x[m] for m in ("input_screen", "hardened_prompt", "output_redaction", "output_contract"))
    assert c.get("/api/defense/presets", headers=hdr(h, "red_team")).status_code == 403
