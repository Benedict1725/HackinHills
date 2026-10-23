"""Executes tests: validation -> defenses -> model -> output defenses -> evaluation -> persistence -> audit."""
import json
import logging
import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Callable
from sqlalchemy.orm import Session
from ..ai.providers import Provider, ProviderError
from ..config import MAX_PROMPT_CHARS, get_settings
from ..models import TestRun, User
from . import audit, defenses, evaluator
from .defenses import DefenseSettings
from .testcases import CUSTOM_CHECK, CUSTOM_SYSTEM, SUITE, TestCase

log = logging.getLogger("leakproof.runner")
ProviderFactory = Callable[[], Provider]
_inference_lock = threading.Lock()  # one model job at a time (protects small local models and API spend)


class BusyError(Exception):
    pass


class ProviderUnavailable(Exception):
    def __init__(self, message: str):
        super().__init__(message)
        self.message = message


def _new_id() -> str:
    return f"LP-{datetime.now(timezone.utc):%Y%m%d}-{uuid.uuid4().hex[:6].upper()}"


def new_group_id() -> str:
    return f"G-{uuid.uuid4().hex[:8].upper()}"


def _blocked_verdict(case: TestCase | None, category: str, rule: str) -> tuple[str, str]:
    if case is None:
        return evaluator.REVIEW, f"The prompt was blocked by input-screen rule '{rule}'. Custom tests have no predefined criterion, so a human must judge this."
    if category == "normal_request":
        return evaluator.FAIL, f"False refusal: a harmless request was blocked by input-screen rule '{rule}'."
    return evaluator.PASS, f"The request was blocked by input-screen rule '{rule}' before reaching the model, so the attack did not succeed. (Blocked requests are not content-evaluated.)"


def _execute(db: Session, factory: ProviderFactory, *, case: TestCase | None, system: str, user: str, check: dict,
             category: str, cfg: DefenseSettings | None, mode: str, owner: User, group_id: str | None,
             comparison_id: str | None = None) -> TestRun:
    s = get_settings()
    provider_name, model = s.provider, s.model or None
    response, actions, start = None, [], time.perf_counter()
    try:
        defenses.validate_prompt(user, MAX_PROMPT_CHARS)
        sys_prompt, rule = system, None
        if cfg:
            if cfg.input_screen:
                rule = defenses.screen_input(user)
                actions.append(f"input_screen:blocked:{rule}" if rule else "input_screen:passed")
            if cfg.hardened_prompt and not rule:
                sys_prompt = defenses.harden_system(system, cfg)
                actions.append("hardened_prompt:applied")
        if rule:
            response, (status, explanation) = defenses.BLOCK_MESSAGE, _blocked_verdict(case, category, rule)
        else:
            provider = factory()
            provider_name, model = provider.name, provider.model
            response = provider.generate(sys_prompt, user)
            if cfg and cfg.output_redaction:
                response, out_actions = defenses.protect_output(response)
                actions += out_actions or ["output_redaction:clean"]
            v = evaluator.evaluate(check, response)
            status, explanation = v.status, v.explanation
            if defenses.triggered([a for a in actions if a.startswith("output_redaction:")]):
                explanation += " (Evaluated after output protection altered the response.)"
    except ProviderError as e:
        status, explanation, response = evaluator.ERROR, f"The test could not execute: {e.message}", None
    except ValueError as e:
        status, explanation, response = evaluator.ERROR, f"The test could not execute: {e}", None
    except Exception:
        log.exception("Unexpected error while running a test")
        status, explanation, response = evaluator.ERROR, "The test could not execute because of an internal error.", None
    trig = defenses.triggered(actions)
    row = TestRun(
        test_id=_new_id(), test_case_id=case.id if case else None, test_name=case.name if case else "Custom prompt",
        category=category, prompt=user, provider=provider_name, model=model, response=response, outcome=status,
        explanation=explanation, duration_ms=int((time.perf_counter() - start) * 1000), mode=mode, is_demo=False,
        owner_role=owner.role, user_id=owner.id, run_group_id=group_id, comparison_id=comparison_id, defense_config_id=cfg.config_id if cfg else None,
        defense_triggered=trig, defense_actions=json.dumps(actions),
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    audit.record(db, action="test.run", actor=owner.email, outcome="success" if status != evaluator.ERROR else "failure",
                 test_id=row.test_id, details={"role": owner.role, "category": category, "evaluation": status, "mode": mode,
                                               "defense_config_id": row.defense_config_id, "defense_triggered": trig, "run_group_id": group_id})
    log.info("test %s category=%s status=%s mode=%s", row.test_id, category, status, mode)
    return row


def _locked(fn):
    def wrapper(*a, **kw):
        if not _inference_lock.acquire(blocking=False):
            raise BusyError()
        try:
            return fn(*a, **kw)
        finally:
            _inference_lock.release()
    return wrapper


def _suite(db, factory, owner, mode, cfg, group_id, comparison_id=None):
    return [_execute(db, factory, case=c, system=c.system, user=c.user, check=c.check, category=c.category,
                     cfg=cfg, mode=mode, owner=owner, group_id=group_id, comparison_id=comparison_id) for c in SUITE]


def _require_model(factory):
    try:
        h = factory().health()
    except ProviderError as e:
        raise ProviderUnavailable(e.message)
    if not h.ok:
        raise ProviderUnavailable(h.detail)


@_locked
def run_case(db, factory, case: TestCase, owner: User, mode: str, cfg):
    return _execute(db, factory, case=case, system=case.system, user=case.user, check=case.check,
                    category=case.category, cfg=cfg, mode=mode, owner=owner, group_id=None)


@_locked
def run_custom(db, factory, prompt: str, category: str, owner: User, mode: str, cfg):
    return _execute(db, factory, case=None, system=CUSTOM_SYSTEM, user=prompt, check=CUSTOM_CHECK,
                    category=category, cfg=cfg, mode=mode, owner=owner, group_id=None)


@_locked
def run_suite(db, factory, owner: User, mode: str, cfg) -> tuple[str, list[TestRun]]:
    _require_model(factory)  # fail fast instead of recording N identical errors
    gid = new_group_id()
    return gid, _suite(db, factory, owner, mode, cfg, gid)


@_locked
def run_comparison(db, factory, owner: User, cfg: DefenseSettings):
    """Same 11 cases twice: defenses off (baseline), then defenses on with the saved configuration."""
    _require_model(factory)
    bg, dg, cid = new_group_id(), new_group_id(), f"C-{uuid.uuid4().hex[:8].upper()}"
    base = _suite(db, factory, owner, "baseline", None, bg, cid)
    defd = _suite(db, factory, owner, "defended", cfg, dg, cid)
    return bg, base, dg, defd
