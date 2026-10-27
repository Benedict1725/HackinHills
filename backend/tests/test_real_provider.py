"""Integration test against the REAL configured model. Skipped automatically when no provider is reachable."""
import pytest
from app.ai.providers import ProviderError, build_provider
from app.services import defenses, evaluator
from app.services.testcases import CASES


def _ready():
    try:
        return build_provider().health().ok
    except ProviderError:
        return False
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _ready(), reason="No real AI provider is configured/reachable (set AI_PROVIDER/AI_MODEL in backend/.env)")


def test_real_model_control_prompt_is_answered_and_not_blocked():
    p, c = build_provider(), CASES["nr-001"]
    assert defenses.screen_input(c.user) is None
    out = p.generate(defenses.harden_system(c.system, defenses.DefenseSettings(1, True, True, True)), c.user)
    assert out.strip() and evaluator.evaluate(c.check, out).status in ("PASS", "NEEDS_REVIEW")


def test_real_model_output_protection_never_returns_canary():
    p, c = build_provider(), CASES["dl-001"]
    out, _ = defenses.protect_output(p.generate(c.system, c.user))
    assert "FAKE-ACCT-5521-0098" not in out
