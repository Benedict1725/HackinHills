import hashlib
import json
import threading
import pytest
from sqlalchemy import text
from app.models import AuditEvent
from app.services import audit
from tests.conftest import PASSWORD, FakeProvider, audit_rows


def seed(Session, n=5):
    with Session() as db:
        for i in range(n):
            audit.record(db, action=f"test.event{i}", actor="svc", outcome="success", test_id=f"T{i}", details={"i": i, "nested": {"b": 2, "a": 1}})


def verify(Session):
    with Session() as db:
        return audit.verify_chain(db)


def raw(engine, sql, **p):
    with engine.begin() as c:
        c.execute(text(sql), p)


def test_empty_chain_verifies(env):
    assert verify(env[2]).ok and verify(env[2]).checked == 0


def test_chain_links_and_verifies(env):
    _, _, Session, _ = env
    seed(Session)
    ev = audit_rows(Session)
    assert ev[0].prev_hash == audit.GENESIS
    assert all(ev[i].prev_hash == ev[i - 1].event_hash for i in range(1, 5))
    v = verify(Session)
    assert v.ok and v.checked == 5 and v.head_hash == ev[-1].event_hash and v.first_inconsistency is None


def test_hash_algorithm_is_the_documented_sha256_over_canonical_json(env):
    _, _, Session, _ = env
    seed(Session, 2)
    e = audit_rows(Session)[1]
    body = {"id": e.id, "ts": e.ts, "actor": e.actor, "action": e.action, "test_id": e.test_id, "outcome": e.status,
            "details": e.details, "prev_hash": e.prev_hash}
    expected = hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()
    assert e.event_hash == expected and len(expected) == 64


def test_canonicalisation_ignores_dict_key_order():
    a = AuditEvent(id=1, ts="t", actor="a", action="x", test_id=None, status="success", details={"a": 1, "b": 2}, prev_hash="0" * 64)
    b = AuditEvent(id=1, ts="t", actor="a", action="x", test_id=None, status="success", details={"b": 2, "a": 1}, prev_hash="0" * 64)
    assert audit.compute_hash(a) == audit.compute_hash(b)


@pytest.mark.parametrize("col,value", [("action", "tampered"), ("actor", "mallory"), ("status", "success-forged"), ("test_id", "T-FORGED"),
                                       ("ts", "2020-01-01T00:00:00+00:00"), ("details", '{"i": 999}')])
def test_modified_record_is_detected_at_that_event(env, col, value):
    _, _, Session, engine = env
    seed(Session)
    target = audit_rows(Session)[2].id
    raw(engine, f"UPDATE audit_events SET {col} = :v WHERE id = :i", v=value, i=target)
    v = verify(Session)
    assert not v.ok
    assert v.first_inconsistency["event_id"] == target and v.first_inconsistency["kind"] == "hash_mismatch"


def test_deleted_middle_record_breaks_link(env):
    _, _, Session, engine = env
    seed(Session)
    ids = [e.id for e in audit_rows(Session)]
    raw(engine, "DELETE FROM audit_events WHERE id = :i", i=ids[2])
    v = verify(Session)
    assert not v.ok and v.first_inconsistency["event_id"] == ids[3] and v.first_inconsistency["kind"] == "broken_link"


def test_relinked_record_with_valid_own_hash_still_breaks_link(env):
    _, _, Session, engine = env
    seed(Session)
    with Session() as db:  # attacker repoints prev_hash AND recomputes that one event's hash
        e = db.get(AuditEvent, audit_rows(Session)[3].id)
        e.prev_hash = "f" * 64
        e.event_hash = audit.compute_hash(e)
        db.commit()
        target = e.id
    v = verify(Session)
    assert not v.ok and v.first_inconsistency["event_id"] == target and v.first_inconsistency["kind"] == "broken_link"


def test_first_inconsistency_is_the_earliest(env):
    _, _, Session, engine = env
    seed(Session)
    ids = [e.id for e in audit_rows(Session)]
    raw(engine, "UPDATE audit_events SET action='x' WHERE id = :i", i=ids[4])
    raw(engine, "UPDATE audit_events SET action='y' WHERE id = :i", i=ids[1])
    assert verify(Session).first_inconsistency["event_id"] == ids[1]


def test_missing_hash_is_flagged(env):
    _, _, Session, engine = env
    seed(Session, 3)
    raw(engine, "UPDATE audit_events SET event_hash = NULL WHERE id = 2")
    assert verify(Session).first_inconsistency["kind"] == "missing_hash"


def test_documented_limit_tail_truncation_and_full_rewrite_are_not_detected(env):
    """Honest limitation: without an external checkpoint these attacks evade the chain."""
    _, _, Session, engine = env
    seed(Session)
    last = audit_rows(Session)[-1].id
    raw(engine, "DELETE FROM audit_events WHERE id = :i", i=last)
    assert verify(Session).ok            # newest event silently removed
    with Session() as db:                # attacker rewrites every event consistently
        prev = audit.GENESIS
        for e in db.query(AuditEvent).order_by(AuditEvent.id):
            e.action = "rewritten"; e.prev_hash = prev; e.event_hash = audit.compute_hash(e); prev = e.event_hash
        db.commit()
    assert verify(Session).ok


def test_concurrent_appends_keep_a_valid_chain(env):
    _, _, Session, _ = env
    def work(k):
        with Session() as db:
            for i in range(5):
                audit.record(db, action="c.event", actor=f"t{k}", outcome="success", details={"i": i})
    ts = [threading.Thread(target=work, args=(k,)) for k in range(4)]
    [t.start() for t in ts]; [t.join() for t in ts]
    v = verify(Session)
    assert v.ok and v.checked == 20


# ---- API behaviour
def test_verify_endpoint_reports_real_result_and_logs_the_attempt(env):
    c, h, Session, engine = env
    a = h["hdr"]["admin"]
    seed(Session)
    r = c.post("/api/audit/verify", headers=a).json()
    assert r["result"] == "VERIFIED" and r["events_checked"] == 5 and r["first_inconsistency"] is None and "rewrites the entire chain" in r["note"]
    raw(engine, "UPDATE audit_events SET action='tampered' WHERE id = 3")
    r = c.post("/api/audit/verify", headers=a).json()
    assert r["result"] == "INTEGRITY FAILURE" and r["first_inconsistency"]["event_id"] == 3
    verifies = [e for e in audit_rows(Session) if e.action == "audit.verify"]
    assert [e.status for e in verifies] == ["success", "failure"] and verifies[1].details["result"] == "INTEGRITY FAILURE"


def test_audit_api_is_read_only(env):
    c, h, Session, _ = env
    seed(Session, 2)
    before = [e.event_hash for e in audit_rows(Session)]
    for hdr in (h["hdr"]["admin"], h["hdr"]["red_team"]):
        for m in ("PUT", "PATCH", "DELETE"):
            for p in ("/api/audit", "/api/audit/1"):
                assert c.request(m, p, headers=hdr, json={"action": "x"}).status_code in (404, 405, 403)
        assert c.post("/api/audit", headers=hdr, json={"action": "forged"}).status_code in (404, 405)
    assert [e.event_hash for e in audit_rows(Session)][:2] == before


def test_audit_list_filters_and_pagination(env):
    c, h, Session, _ = env
    seed(Session, 4)
    a = h["hdr"]["admin"]
    d = c.get("/api/audit?action=test.event&limit=2", headers=a).json()
    assert d["total"] == 4 and len(d["items"]) == 2 and d["items"][0]["event_hash"]
    assert c.get("/api/audit?limit=9999", headers=a).status_code == 422


def test_events_recorded_for_tests_config_login_denials_and_verification(env):
    c, h, Session, _ = env
    c.post("/api/auth/login", json={"email": "red_team@test.local", "password": PASSWORD}, headers={"Authorization": ""})
    c.post("/api/defense/config", json={}, headers=h["hdr"]["blue_team"])
    h["provider"] = FakeProvider("ok")
    tid = c.post("/api/tests/run", json={"test_case_id": "nr-001"}).json()["test_id"]
    c.get("/api/defense/config")                                   # red team -> denied
    c.post("/api/audit/verify", headers=h["hdr"]["admin"])
    ev = audit_rows(Session)
    assert [e.action for e in ev] == ["auth.login", "defense.config.update", "test.run", "authz.denied", "audit.verify"]
    assert ev[2].test_id == tid and ev[2].details["evaluation"] in ("PASS", "FAIL", "NEEDS_REVIEW")
    assert all(e.ts and e.actor and e.event_hash and e.prev_hash for e in ev)
    assert verify(Session).ok


def test_no_secrets_prompts_or_tokens_in_audit_log(env):
    c, h, Session, _ = env
    r = c.post("/api/auth/login", json={"email": "red_team@test.local", "password": PASSWORD}, headers={"Authorization": ""}).json()
    h["provider"] = FakeProvider("The code is LP-DEMO-CODE-4471-ZQ")
    c.post("/api/tests/run", json={"prompt": "UNIQUE-PROMPT-MARKER-XYZ please", "category": "jailbreak"})
    c.post("/api/defense/config", json={"policy_text": "UNIQUE-POLICY-MARKER"}, headers=h["hdr"]["blue_team"])
    dump = json.dumps([(e.actor, e.action, e.details, e.test_id) for e in audit_rows(Session)])
    for forbidden in (PASSWORD, r["token"], "UNIQUE-PROMPT-MARKER-XYZ", "UNIQUE-POLICY-MARKER", "LP-DEMO-CODE-4471-ZQ", "ANTHROPIC_API_KEY", "sk-ant"):
        assert forbidden not in dump


def test_restart_keeps_audit_and_chain_valid(env):
    _, _, Session, engine = env
    seed(Session, 3)
    url = str(engine.url); engine.dispose()
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    S2 = sessionmaker(bind=create_engine(url))
    with S2() as db:
        audit.record(db, action="after.restart", actor="svc", outcome="success")
    assert verify(S2).ok and verify(S2).checked == 4
