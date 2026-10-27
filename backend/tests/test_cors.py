def test_500_still_carries_cors_header(env, monkeypatch):
    from app.routes import tests as t
    c, *_ = env
    monkeypatch.setattr(t, "CASES", None)
    r = c.post("/api/tests/run", json={"test_case_id": "jb-001"}, headers={"Origin": "http://localhost:5173"})
    assert r.status_code == 500 and r.headers["access-control-allow-origin"] == "http://localhost:5173"


def test_preflight_allows_local_dev_ports_and_authorization_header(env):
    c, *_ = env
    for origin in ("http://localhost:5173", "http://127.0.0.1:5174", "http://localhost:5180"):
        r = c.options("/api/tests/run", headers={"Origin": origin, "Access-Control-Request-Method": "POST", "Access-Control-Request-Headers": "authorization,content-type"})
        assert r.status_code == 200 and r.headers["access-control-allow-origin"] == origin


def test_foreign_origin_is_not_allowed(env):
    c, *_ = env
    r = c.get("/api/health", headers={"Origin": "https://evil.example"})
    assert "access-control-allow-origin" not in r.headers
    r = c.options("/api/tests/run", headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "POST"})
    assert r.status_code == 400
