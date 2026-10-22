import os
from dataclasses import dataclass, field
from dotenv import load_dotenv

load_dotenv()
MAX_PROMPT_CHARS = 2000


def _int(name: str, default: int, lo: int, hi: int) -> int:
    try:
        return max(lo, min(hi, int(os.getenv(name, default))))
    except ValueError:
        return default


@dataclass(frozen=True)
class Settings:
    provider: str
    model: str
    ollama_host: str
    timeout: int
    max_tokens: int
    anthropic_api_key: str = field(default="", repr=False)  # never logged or returned


def get_settings() -> Settings:
    """Read env on every call so config changes and test monkeypatching take effect."""
    return Settings(
        provider=os.getenv("AI_PROVIDER", "ollama").strip().lower(),
        model=os.getenv("AI_MODEL", "").strip(),
        ollama_host=os.getenv("OLLAMA_HOST", "http://127.0.0.1:11434").rstrip("/"),
        timeout=_int("AI_TIMEOUT_SECONDS", 60, 5, 300),
        max_tokens=_int("AI_MAX_TOKENS", 300, 16, 1000),
        anthropic_api_key=os.getenv("ANTHROPIC_API_KEY", "").strip(),
    )
