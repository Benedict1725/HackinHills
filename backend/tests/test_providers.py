import httpx
import pytest
from app.ai.providers import AnthropicProvider, OllamaProvider, ProviderError, build_provider
from app.config import Settings


def S(**kw):
    d = dict(provider="ollama", model="m1", ollama_host="http://ollama.test", timeout=5, max_tokens=50)
    d.update(kw)
    return Settings(**d)


def mock_httpx(monkeypatch, handler):
    transport = httpx.MockTransport(handler)
    real_get, real_post = httpx.get, httpx.post
    monkeypatch.setattr(httpx, "get", lambda url, **kw: httpx.Client(transport=transport).get(url, **kw))
    monkeypatch.setattr(httpx, "post", lambda url, **kw: httpx.Client(transport=transport).post(url, **kw))


def test_ollama_success(monkeypatch):
    seen = {}
    def h(req):
        seen["body"] = req.content
        return httpx.Response(200, json={"message": {"content": "hello"}})
    mock_httpx(monkeypatch, h)
    assert OllamaProvider(S()).generate("sys", "hi") == "hello"
    assert b'"stream":false' in seen["body"].replace(b" ", b"")


def test_ollama_unreachable(monkeypatch):
    def h(req): raise httpx.ConnectError("boom")
    mock_httpx(monkeypatch, h)
    with pytest.raises(ProviderError) as e:
        OllamaProvider(S()).generate("s", "u")
    assert e.value.code == "unavailable" and "boom" not in e.value.message


def test_ollama_timeout(monkeypatch):
    def h(req): raise httpx.ReadTimeout("slow")
    mock_httpx(monkeypatch, h)
    with pytest.raises(ProviderError) as e:
        OllamaProvider(S()).generate("s", "u")
    assert e.value.code == "timeout"


def test_ollama_model_missing(monkeypatch):
    mock_httpx(monkeypatch, lambda req: httpx.Response(404, json={"error": "model not found"}))
    with pytest.raises(ProviderError) as e:
        OllamaProvider(S()).generate("s", "u")
    assert e.value.code == "model_not_found" and "ollama pull m1" in e.value.message


def test_ollama_bad_json_shape(monkeypatch):
    mock_httpx(monkeypatch, lambda req: httpx.Response(200, json={"nope": 1}))
    with pytest.raises(ProviderError) as e:
        OllamaProvider(S()).generate("s", "u")
    assert e.value.code == "bad_response"


def test_ollama_health_states(monkeypatch):
    mock_httpx(monkeypatch, lambda req: httpx.Response(200, json={"models": [{"name": "m1:latest"}]}))
    assert OllamaProvider(S()).health().ok
    assert not OllamaProvider(S(model="other")).health().ok
    def down(req): raise httpx.ConnectError("x")
    mock_httpx(monkeypatch, down)
    assert not OllamaProvider(S()).health().ok


def test_build_provider_validation():
    with pytest.raises(ProviderError): build_provider(S(model=""))
    with pytest.raises(ProviderError): build_provider(S(provider="nope"))
    with pytest.raises(ProviderError) as e: build_provider(S(provider="anthropic"))
    assert "ANTHROPIC_API_KEY" in e.value.message


def test_anthropic_success_and_error_translation():
    p = AnthropicProvider(S(provider="anthropic", anthropic_api_key="test-key-not-real"))
    class Block: type, text = "text", "hi there"
    class Msg: content = [Block()]
    p.client = type("C", (), {"messages": type("M", (), {"create": staticmethod(lambda **kw: Msg())})()})()
    assert p.generate("s", "u") == "hi there"
    import anthropic, httpx as hx
    req = hx.Request("POST", "https://x")
    def boom(**kw): raise anthropic.APIConnectionError(request=req)
    p.client = type("C", (), {"messages": type("M", (), {"create": staticmethod(boom)})()})()
    with pytest.raises(ProviderError) as e:
        p.generate("s", "u")
    assert e.value.code == "unavailable"
