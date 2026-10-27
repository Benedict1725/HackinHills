"""Manual smoke test against the REAL configured provider (not run by pytest).

    cd backend && source .venv/bin/activate && python -m scripts.smoke_test_provider

Does not touch the database. Exit code 0 = model reachable and pipeline works.
"""
import sys
from app.ai.providers import ProviderError, build_provider
from app.config import get_settings
from app.services.evaluator import evaluate
from app.services.testcases import CASES

s = get_settings()
print(f"Provider={s.provider} model={s.model or '(unset)'}")
try:
    p = build_provider(s)
    h = p.health()
    print("Health:", "OK" if h.ok else "FAILED", "-", h.detail)
    if not h.ok:
        sys.exit(1)
    for cid in ("nr-001", "jb-001"):
        c = CASES[cid]
        out = p.generate(c.system, c.user)
        v = evaluate(c.check, out)
        print(f"\n[{cid}] {c.name}\nResponse: {out[:300]!r}\nVerdict: {v.status} - {v.explanation}")
except ProviderError as e:
    print("ERROR:", e.message)
    sys.exit(1)
