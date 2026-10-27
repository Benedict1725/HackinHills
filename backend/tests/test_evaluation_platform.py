from sqlalchemy import select
from app.models import TestRun
from app.services.testcases import CASES, SUITE_VERSION
from tests.conftest import FakeProvider


def test_library_has_versioned_metadata_and_capability_boundaries(env):
    c, h, *_ = env
    data = c.get("/api/test-cases").json()
    item = next(x for x in data["cases"] if x["id"] == "pi-001")
    assert item["severity"] == "high" and item["owasp"] and item["availability"] == "implemented"
    unavailable = next(x for x in data["cases"] if x["id"] == "pi-rag-001")
    assert unavailable["availability"] == "requires:rag"
    assert c.post("/api/tests/run", json={"test_case_id": unavailable["id"]}).status_code == 409


def test_repeated_trials_are_persisted_with_provenance(env):
    c, h, Session, _ = env
    h["provider"] = FakeProvider("Paris")
    result = c.post("/api/tests/run", json={"test_case_id": "nr-001", "trials": 3})
    assert result.status_code == 201
    with Session() as db:
        rows = db.scalars(select(TestRun).where(TestRun.test_case_id == "nr-001").order_by(TestRun.id)).all()
        assert [r.trial_number for r in rows] == [1, 2, 3]
        assert {r.test_suite_version for r in rows} == {SUITE_VERSION}


def test_report_sanitizes_evidence_and_keeps_ambiguous_visible(env):
    c, h, *_ = env
    h["provider"] = FakeProvider("")
    assert c.post("/api/tests/run", json={"test_case_id": "nr-001"}).status_code == 201
    report = c.get("/api/reports/evaluation")
    assert report.status_code == 200
    data = report.json()
    assert data["metrics"]["NEEDS_REVIEW"] == 1
    assert data["outcomes"][0]["test_suite_version"] == SUITE_VERSION
    assert "universal model safety score" in " ".join(data["limitations"])


def test_human_review_is_recorded_without_changing_evaluator_verdict(env):
    c, h, *_ = env
    h["provider"] = FakeProvider("")
    run = c.post("/api/tests/run", json={"test_case_id": "nr-001"}).json()
    reviewed = c.post(f"/api/tests/{run['test_id']}/review", json={"status": "CONFIRMED"}, headers=h["hdr"]["blue_team"])
    assert reviewed.status_code == 403  # Blue Team cannot alter a Red Team artifact.
    # Admin can document review, but the deterministic NEEDS_REVIEW verdict is preserved.
    reviewed = c.post(f"/api/tests/{run['test_id']}/review", json={"status": "CONFIRMED"}, headers=h["hdr"]["admin"])
    assert reviewed.json()["outcome"] == "NEEDS_REVIEW"
    assert reviewed.json()["human_review_status"] == "CONFIRMED"
