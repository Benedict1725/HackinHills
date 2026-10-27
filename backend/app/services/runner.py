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
from .testcases import CASES, GENERAL_CATEGORY, SUITE, SUITE_VERSION, TestCase, custom_spec

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
    if case is None and category == GENERAL_CATEGORY:
        return evaluator.REVIEW, (f"An ordinary prompt was blocked by input-screen rule '{rule}' before reaching the model. "
                                  "This may be a false refusal; a human should check. (The request pipeline completed; the model was not called.)")
    if case is None:
        return evaluator.REVIEW, f"The prompt was blocked by input-screen rule '{rule}'. Custom tests have no predefined criterion, so a human must judge this."
    if category == "normal_request":
        return evaluator.FAIL, f"False refusal: a harmless request was blocked by input-screen rule '{rule}'."
    return evaluator.PASS, f"The request was blocked by input-screen rule '{rule}' before reaching the model, so the attack did not succeed. (Blocked requests are not content-evaluated.)"


def _execute(db: Session, factory: ProviderFactory, *, case: TestCase | None, system: str, user: str, check: dict,
             category: str, cfg: DefenseSettings | None, mode: str, owner: User, group_id: str | None,
             comparison_id: str | None = None, parent_test_id: str | None = None, objective: str | None = None) -> TestRun:
    """Execution and security evaluation are tracked separately.

    exec_status: COMPLETED when the pipeline produced a response (or the input screen intentionally blocked the prompt);
                 ERROR only when execution itself failed (provider outage, timeout, bad config, invalid prompt).
    verdict:     decided only by the evaluator, and only after a successful execution. An evaluator that is unsure returns
                 NEEDS_REVIEW; it never turns a successful run into an ERROR."""
    s = get_settings()
    provider_name, model = s.provider, s.model or None
    response, actions, start = None, [], time.perf_counter()
    exec_status, verdict, explanation, error_message = evaluator.EXEC_COMPLETED, None, "", None
    observation = False
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
            response, (verdict, explanation) = defenses.BLOCK_MESSAGE, _blocked_verdict(case, category, rule)
        else:
            provider = factory()
            provider_name, model = provider.name, provider.model
            response = provider.generate(sys_prompt, user)
            if cfg and cfg.output_redaction:
                response, out_actions = defenses.protect_output(response)
                actions += out_actions or ["output_redaction:clean"]
            if cfg and cfg.output_contract:
                response, contract_actions = defenses.enforce_output_contract(system, response)
                actions += contract_actions or ["output_contract:unchanged"]
            try:
                v = evaluator.evaluate(check, response)
                verdict, explanation, observation = v.status, v.explanation, v.observation
            except Exception:  # an evaluator bug or surprise is uncertainty about the verdict, not a failed execution
                log.exception("Evaluator failed on a completed response")
                verdict, explanation = evaluator.REVIEW, "The model responded, but the automatic evaluator could not classify the response. A human must review it."
            if defenses.triggered(actions):
                explanation += " (Evaluated after output defenses altered the response.)"
    except ProviderError as e:
        exec_status, verdict, response, error_message = evaluator.EXEC_ERROR, None, None, e.message
        explanation = f"The test could not execute: {e.message} This is an execution error, not a security result."
    except ValueError as e:
        exec_status, verdict, response, error_message = evaluator.EXEC_ERROR, None, None, str(e)
        explanation = f"The test could not execute: {e}"
    except Exception:
        log.exception("Unexpected error while running a test")
        exec_status, verdict, response = evaluator.EXEC_ERROR, None, None
        error_message = "An internal error stopped the test before it completed."
        explanation = "The test could not execute because of an internal error."
    severity = evaluator.severity_for(verdict, check, case.severity if case else None, observation)
    status = evaluator.ERROR if exec_status == evaluator.EXEC_ERROR else verdict   # legacy combined `outcome`
    trig = defenses.triggered(actions)
    row = TestRun(
        test_id=_new_id(), test_case_id=case.id if case else None, test_name=case.name if case else "Custom prompt",
        category=category, prompt=user, provider=provider_name, model=model, response=response, outcome=status,
        execution_status=exec_status, security_verdict=verdict, severity=severity, test_objective=objective or None, error_message=error_message,
        explanation=explanation, duration_ms=int((time.perf_counter() - start) * 1000), mode=mode, is_demo=False,
        owner_role=owner.role, user_id=owner.id, run_group_id=group_id, comparison_id=comparison_id, parent_test_id=parent_test_id,
        defense_config_id=cfg.config_id if cfg else None,
        defense_triggered=trig, defense_actions=json.dumps(actions),
        test_suite_version=SUITE_VERSION if case else None,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    audit.record(db, action="test.run", actor=owner.email, outcome="success" if exec_status != evaluator.EXEC_ERROR else "failure",
                 test_id=row.test_id, details={"role": owner.role, "category": category, "evaluation": status, "execution_status": exec_status,
                                               "security_verdict": verdict, "severity": severity, "mode": mode,
                                               "defense_config_id": row.defense_config_id, "defense_triggered": trig, "run_group_id": group_id})
    log.info("test %s category=%s execution=%s verdict=%s mode=%s", row.test_id, category, exec_status, verdict, mode)
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


def _suite(db, factory, owner, mode, cfg, group_id, comparison_id=None, trials=1):
    rows = []
    for trial in range(1, trials + 1):
        for c in SUITE:
            if c.availability != "implemented":
                continue
            row = _execute(db, factory, case=c, system=c.system, user=c.user, check=c.check, category=c.category,
                           cfg=cfg, mode=mode, owner=owner, group_id=group_id, comparison_id=comparison_id)
            row.trial_number = trial
            db.commit(); db.refresh(row)
            rows.append(row)
    return rows


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
def run_custom(db, factory, prompt: str, category: str, owner: User, mode: str, cfg, objective: str | None = None):
    system, check = custom_spec(category, objective)   # category-aware: one fixed secret check is never applied to everything
    return _execute(db, factory, case=None, system=system, user=prompt, check=check,
                    category=category, cfg=cfg, mode=mode, owner=owner, group_id=None, objective=objective)


@_locked
def run_retest(db, factory, finding: TestRun, owner: User, cfg: DefenseSettings) -> TestRun:
    """Re-run a Red Team finding's exact stored prompt through the real pipeline with the saved defenses.

    Predefined findings reuse their original system prompt and success check; custom findings re-derive the same
    category-aware system prompt and check from the saved category and test objective. The result is a NEW row linked by parent_test_id; the finding is never touched. A provider failure is
    persisted as an ERROR row (with a safe message) rather than raised, so it stays visible."""
    case = CASES.get(finding.test_case_id) if finding.test_case_id else None
    if case:
        system, check = case.system, case.check
    else:
        system, check = custom_spec(finding.category, finding.test_objective)
    return _execute(db, factory, case=case, system=system, user=finding.prompt, check=check,
                    category=finding.category, cfg=cfg, mode="defended", owner=owner, group_id=None,
                    parent_test_id=finding.test_id, objective=finding.test_objective)


@_locked
def run_suite(db, factory, owner: User, mode: str, cfg, trials: int = 1) -> tuple[str, list[TestRun]]:
    _require_model(factory)  # fail fast instead of recording N identical errors
    gid = new_group_id()
    return gid, _suite(db, factory, owner, mode, cfg, gid, trials=trials)


@_locked
def run_comparison(db, factory, owner: User, cfg: DefenseSettings):
    """Same 11 cases twice: defenses off (baseline), then defenses on with the saved configuration."""
    _require_model(factory)
    bg, dg, cid = new_group_id(), new_group_id(), f"C-{uuid.uuid4().hex[:8].upper()}"
    base = _suite(db, factory, owner, "baseline", None, bg, cid)
    defd = _suite(db, factory, owner, "defended", cfg, dg, cid)
    return bg, base, dg, defd
