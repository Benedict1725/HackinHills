import importlib
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import sessionmaker
from tests.conftest import FakeProvider


def test_results_survive_new_session_and_engine(env, tmp_path):
    c, h, Session, engine = env
    h["provider"] = FakeProvider("nope")
    tid = c.post("/api/tests/run", json={"test_case_id": "dl-001"}).json()["test_id"]
    url = str(engine.url)
    engine.dispose()
    fresh = sessionmaker(bind=create_engine(url))()  # simulates a backend restart
    row = fresh.execute(text("select test_id, outcome, response, explanation, duration_ms, provider, model, category, test_name from test_runs")).one()
    assert row[0] == tid and row[1] == "PASS" and row[2] == "nope" and row[3] and row[4] is not None
    assert row[5:] == ("mock", "mock-1", "data_leakage", "Unverified user requests a customer record")


def test_test_ids_are_unique(env):
    c, h, *_ = env
    ids = {c.post("/api/tests/run", json={"test_case_id": "nr-001"}).json()["test_id"] for _ in range(5)}
    assert len(ids) == 5


def test_day1_database_is_migrated(tmp_path, monkeypatch):
    url = f"sqlite:///{tmp_path/'old.db'}"
    eng = create_engine(url)
    with eng.begin() as c:  # Day 1 schema
        c.execute(text("CREATE TABLE test_runs (id INTEGER PRIMARY KEY, category VARCHAR(64), prompt TEXT, model VARCHAR(100), mode VARCHAR(16), response TEXT, outcome VARCHAR(16), is_demo BOOLEAN, defense_config_id INTEGER, user_id INTEGER, created_at DATETIME)"))
        c.execute(text("INSERT INTO test_runs (category,prompt,outcome,is_demo) VALUES ('x','old','pending',0)"))
    import app.database as d
    monkeypatch.setattr(d, "engine", eng)
    d.migrate_day1_schema()
    cols = {c["name"] for c in inspect(eng).get_columns("test_runs")}
    assert {"test_id", "explanation", "duration_ms", "provider", "test_name", "test_case_id"} <= cols
    d.migrate_day1_schema()  # idempotent
    with eng.connect() as c:
        assert c.execute(text("select count(*) from test_runs")).scalar() == 1  # old row kept
