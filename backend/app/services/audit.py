"""Tamper-evident audit log: each event stores SHA-256(canonical(event) incl. previous event hash).

Limits: this detects modification, reordering and mid-chain deletion by anyone who cannot
recompute the chain. An attacker with database write access who rewrites EVERY later event
(or truncates the tail) is not detectable without an independently stored checkpoint
(e.g. a periodically recorded head hash kept outside this database)."""
import hashlib
import json
import re
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from sqlalchemy import select
from sqlalchemy.orm import Session
from ..models import AuditEvent

GENESIS = "0" * 64
_lock = threading.Lock()  # serialises appends so the chain stays linear (single-process)
_EMAIL = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,100}$")


def canonical(e) -> str:
    """Deterministic serialisation: fixed key set, sorted keys, no whitespace, ASCII only."""
    body = {
        "id": e.id, "ts": e.ts, "actor": e.actor, "action": e.action, "test_id": e.test_id,
        "outcome": e.status, "details": e.details or {}, "prev_hash": e.prev_hash,
    }
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def compute_hash(e) -> str:
    return hashlib.sha256(canonical(e).encode()).hexdigest()


def safe_identity(email: str | None) -> str:
    """Failed logins may contain a password typed into the email box; only log plausible emails."""
    return email[:100] if email and _EMAIL.match(email) else "unrecognised-identifier"


def record(db: Session, *, action: str, actor: str, outcome: str, test_id: str | None = None,
           details: dict | None = None) -> AuditEvent:
    """Append one event and commit. Never pass prompts, responses, passwords, tokens or API keys in details."""
    with _lock:
        try:
            last = db.scalar(select(AuditEvent).order_by(AuditEvent.id.desc()).limit(1))
            ev = AuditEvent(
                ts=datetime.now(timezone.utc).isoformat(), actor=actor, action=action, test_id=test_id,
                status=outcome, details=details or {}, prev_hash=(last.event_hash if last and last.event_hash else GENESIS),
            )
            db.add(ev)
            db.flush()                   # assigns ev.id, which is part of the hash
            ev.event_hash = compute_hash(ev)
            db.commit()
            return ev
        except Exception:
            db.rollback()                # never leave a half-written event for the next call to commit
            raise


@dataclass
class Verification:
    ok: bool
    checked: int
    head_hash: str | None
    first_inconsistency: dict | None


def verify_chain(db: Session) -> Verification:
    prev_hash, checked, head = GENESIS, 0, None
    for ev in db.scalars(select(AuditEvent).order_by(AuditEvent.id.asc())):
        checked += 1
        if not ev.event_hash or ev.prev_hash is None:
            return Verification(False, checked, head, {"event_id": ev.id, "kind": "missing_hash", "detail": "Event has no stored hash (legacy or altered record)."})
        if ev.prev_hash != prev_hash:
            return Verification(False, checked, head, {"event_id": ev.id, "kind": "broken_link",
                                "detail": "Previous-hash link does not match the preceding event (record removed, reordered or relinked)."})
        if compute_hash(ev) != ev.event_hash:
            return Verification(False, checked, head, {"event_id": ev.id, "kind": "hash_mismatch",
                                "detail": "Recomputed hash differs from the stored hash (record was modified)."})
        prev_hash = head = ev.event_hash
    return Verification(True, checked, head, None)
