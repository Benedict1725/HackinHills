"""Provider adapters. Add a provider by subclassing Provider and registering it in build_provider()."""
from abc import ABC, abstractmethod
from dataclasses import dataclass
import httpx
from ..config import Settings, get_settings


class ProviderError(Exception):
    """Carries a message that is safe to show to users (never a raw upstream exception)."""
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code, self.message = code, message


@dataclass
class ProviderHealth:
    ok: bool
    provider: str
    model: str
    detail: str


class Provider(ABC):
    name: str
    model: str

    @abstractmethod
    def health(self) -> ProviderHealth: ...

    @abstractmethod
    def generate(self, system: str, user: str) -> str: ...


class OllamaProvider(Provider):
    name = "ollama"

    def __init__(self, s: Settings):
        self.model, self.host, self.timeout, self.max_tokens = s.model, s.ollama_host, s.timeout, s.max_tokens

    def health(self) -> ProviderHealth:
        try:
            r = httpx.get(f"{self.host}/api/tags", timeout=5)
            r.raise_for_status()
            names = {m.get("name", "") for m in r.json().get("models", [])}
        except httpx.HTTPError:
            return ProviderHealth(False, self.name, self.model, f"Cannot reach Ollama at {self.host}. Start it with `ollama serve`.")
        except ValueError:
            return ProviderHealth(False, self.name, self.model, "Ollama returned an unreadable response.")
        if self.model not in names and f"{self.model}:latest" not in names:
            return ProviderHealth(False, self.name, self.model, f"Model '{self.model}' is not installed. Run `ollama pull {self.model}`.")
        return ProviderHealth(True, self.name, self.model, "Ollama is reachable and the model is installed.")

    def generate(self, system: str, user: str) -> str:
        body = {
            "model": self.model, "stream": False,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "options": {"temperature": 0, "seed": 0, "num_predict": self.max_tokens},
        }
        try:
            r = httpx.post(f"{self.host}/api/chat", json=body, timeout=self.timeout)
        except httpx.TimeoutException:
            raise ProviderError("timeout", f"The model did not answer within {self.timeout}s.")
        except httpx.HTTPError:
            raise ProviderError("unavailable", f"Cannot reach Ollama at {self.host}. Start it with `ollama serve`.")
        if r.status_code == 404:
            raise ProviderError("model_not_found", f"Model '{self.model}' is not installed. Run `ollama pull {self.model}`.")
        if r.status_code != 200:
            raise ProviderError("unavailable", f"Ollama returned HTTP {r.status_code}.")
        try:
            return r.json()["message"]["content"]
        except (ValueError, KeyError, TypeError):
            raise ProviderError("bad_response", "Ollama returned an unexpected response format.")


class AnthropicProvider(Provider):
    name = "anthropic"

    def __init__(self, s: Settings):
        if not s.anthropic_api_key:
            raise ProviderError("misconfigured", "ANTHROPIC_API_KEY is not set on the backend.")
        import anthropic  # lazy: Ollama users never need it
        self._sdk = anthropic
        self.client = anthropic.Anthropic(api_key=s.anthropic_api_key, timeout=s.timeout, max_retries=0)
        self.model, self.max_tokens, self.timeout = s.model, s.max_tokens, s.timeout

    def _translate(self, e: Exception) -> ProviderError:
        a = self._sdk
        if isinstance(e, a.APITimeoutError):
            return ProviderError("timeout", f"The model did not answer within {self.timeout}s.")
        if isinstance(e, a.APIConnectionError):
            return ProviderError("unavailable", "Cannot reach the Anthropic API.")
        if isinstance(e, a.AuthenticationError):
            return ProviderError("auth", "The Anthropic API key was rejected.")
        if isinstance(e, a.NotFoundError):
            return ProviderError("model_not_found", f"Model '{self.model}' was not found for this API key.")
        if isinstance(e, a.RateLimitError):
            return ProviderError("rate_limited", "The Anthropic API rate limit was reached. Try again shortly.")
        return ProviderError("unavailable", "The Anthropic API returned an error.")

    def health(self) -> ProviderHealth:
        try:
            self.client.models.retrieve(self.model)  # free metadata call, no tokens spent
            return ProviderHealth(True, self.name, self.model, "Anthropic API reachable and model available.")
        except Exception as e:
            return ProviderHealth(False, self.name, self.model, self._translate(e).message)

    def generate(self, system: str, user: str) -> str:
        try:
            m = self.client.messages.create(
                model=self.model, max_tokens=self.max_tokens, system=system,
                messages=[{"role": "user", "content": user}],
            )
        except Exception as e:
            raise self._translate(e)
        return "".join(b.text for b in m.content if getattr(b, "type", "") == "text")


def build_provider(settings: Settings | None = None) -> Provider:
    s = settings or get_settings()
    if not s.model:
        raise ProviderError("misconfigured", "AI_MODEL is not set. Set it in backend/.env.")
    if s.provider == "ollama":
        return OllamaProvider(s)
    if s.provider == "anthropic":
        return AnthropicProvider(s)
    raise ProviderError("misconfigured", f"Unknown AI_PROVIDER '{s.provider}'. Use 'ollama' or 'anthropic'.")
