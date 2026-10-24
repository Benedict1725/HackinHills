from sqlalchemy import text
from app.ai.providers import ProviderError
from app.services.testcases import CANARY_CODE
from tests.conftest import FakeProvider


def test_test_cases_listing(env):
    c, *_ = env
    d = c.get("/api/test-cases").json()
    assert {"prompt_injection", "jailbreak", "data_leakage", "instruction_conflict", "normal_request", "system_prompt_leakage", "improper_output_handling", "misinformation", "resource_consumption"} <= {x["category"] for x in d["cases"]}
    assert CANARY_CODE not in str(d)  # system prompts/secrets are not exposed


def test_run_predefined_pass_persists_and_is_retrievable(env):
    c, h, *_ = env
    h["provider"] = FakeProvider("I'm sorry, I can't share that.")
    r = c.post("/api/tests/run", json={"test_case_id": "jb-001"})
    assert r.status_code == 201
    d = r.json()
    assert d["outcome"] == "PASS" and d["model"] == "mock-1" and d["provider"] == "mock"
    assert d["response"] and d["explanation"] and d["duration_ms"] is not None
    got = c.get(f"/api/tests/{d['test_id']}").json()
    assert got["test_id"] == d["test_id"] and got["response"] == d["response"]
    assert c.get("/api/tests").json()["total"] == 1


def test_leak_is_fail(env):
    c, h, *_ = env
    h["provider"] = FakeProvider(f"Sure! The code is {CANARY_CODE}")
    assert c.post("/api/tests/run", json={"test_case_id": "pi-002"}).json()["outcome"] == "FAIL"


def test_custom_prompt_never_pass(env):
    c, h, *_ = env
    h["provider"] = FakeProvider("Just a normal answer.")
    d = c.post("/api/tests/run", json={"prompt": "hello", "category": "jailbreak"}).json()
    assert d["outcome"] == "NEEDS_REVIEW" and d["test_case_id"] is None


def test_provider_failure_saved_as_error_without_leaking_details(env):
    c, h, *_ = env
    h["provider"] = FakeProvider(error=ProviderError("unavailable", "Cannot reach Ollama at http://x. Start it with `ollama serve`."))
    r = c.post("/api/tests/run", json={"test_case_id": "nr-001"})
    assert r.status_code == 201 and r.json()["outcome"] == "ERROR"
    assert "could not execute" in r.json()["explanation"]
    assert c.get("/api/tests?status=ERROR").json()["total"] == 1


def test_unexpected_exception_is_handled(env):
    c, h, *_ = env
    h["provider"] = FakeProvider(error=RuntimeError("secret-internal-detail"))
    r = c.post("/api/tests/run", json={"test_case_id": "nr-001"})
    assert r.json()["outcome"] == "ERROR" and "secret-internal-detail" not in r.text


def test_invalid_requests(env):
    c, *_ = env
    assert c.post("/api/tests/run", json={}).status_code == 422
    assert c.post("/api/tests/run", json={"prompt": "x"}).status_code == 422
    assert c.post("/api/tests/run", json={"prompt": "  ", "category": "jailbreak"}).status_code == 422
    assert c.post("/api/tests/run", json={"prompt": "x", "category": "bogus"}).status_code == 422
    assert c.post("/api/tests/run", json={"prompt": "x" * 2001, "category": "jailbreak"}).status_code == 422
    assert c.post("/api/tests/run", json={"test_case_id": "jb-001", "prompt": "x", "category": "jailbreak"}).status_code == 422
    assert c.post("/api/tests/run", json={"test_case_id": "nope"}).status_code == 404
    assert c.get("/api/tests/LP-DOES-NOT-EXIST").status_code == 404
    assert c.get("/api/tests?limit=1000").status_code == 422
    assert c.get("/api/tests?status=BOGUS").status_code == 422


def test_suite_runs_all_and_counts(env):
    c, h, *_ = env
    h["provider"] = FakeProvider("Paris is the capital. 12 times 12 is 144. Be concise and clear in every email you write.")
    d = c.post("/api/tests/run-suite").json()
    assert d["total"] == 14 and sum(d["counts"].values()) == 14
    assert c.get("/api/tests").json()["total"] == 14


def test_suite_unavailable_returns_503_and_saves_nothing(env):
    c, h, *_ = env
    h["provider"] = FakeProvider(healthy=False)
    r = c.post("/api/tests/run-suite")
    assert r.status_code == 503 and "unavailable" in r.json()["detail"]
    assert c.get("/api/tests").json()["total"] == 0


def test_busy_returns_429(env):
    from app.services import runner
    c, *_ = env
    runner._inference_lock.acquire()
    try:
        assert c.post("/api/tests/run", json={"test_case_id": "nr-001"}).status_code == 429
        assert c.post("/api/tests/run-suite").status_code == 429
    finally:
        runner._inference_lock.release()


def test_filters_and_dashboard_use_real_data(env):
    c, h, *_ = env
    assert c.get("/api/dashboard").json()["total_tests"] == 0
    assert c.get("/api/dashboard").json()["attack_success_rate"] is None
    h["provider"] = FakeProvider(f"{CANARY_CODE}")
    c.post("/api/tests/run", json={"test_case_id": "jb-001"})       # FAIL (attack)
    h["provider"] = FakeProvider("I can't share that.")
    c.post("/api/tests/run", json={"test_case_id": "jb-002"})       # PASS (attack)
    c.post("/api/tests/run", json={"test_case_id": "nr-001"})       # FAIL (control over-refusal)
    d = c.get("/api/dashboard").json()
    assert (d["total_tests"], d["passed"], d["failed"]) == (3, 1, 2)
    assert d["attack_success_rate"] == 50.0  # controls excluded
    assert c.get("/api/tests?category=jailbreak").json()["total"] == 2
    assert c.get("/api/tests?status=PASS").json()["total"] == 1


def test_ai_health_ok_and_down(env):
    c, h, *_ = env
    assert c.get("/api/ai/health").json()["ok"] is True
    h["provider"] = FakeProvider(healthy=False)
    d = c.get("/api/ai/health").json()
    assert d["ok"] is False and d["detail"] == "mock is down"


def test_unhandled_error_is_generic_500(env, monkeypatch):
    from app.routes import tests as t
    c, *_ = env
    monkeypatch.setattr(t, "CASES", None)
    r = c.post("/api/tests/run", json={"test_case_id": "jb-001"})
    assert r.status_code == 500 and r.json() == {"detail": "Internal server error."}
