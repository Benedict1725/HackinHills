"""Password hashing and session tokens using only the standard library."""
import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone

SESSION_HOURS = 8
_N, _R, _P = 2**14, 8, 1
ROLES = ("red_team", "blue_team", "admin")


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=_N, r=_R, p=_P, dklen=32)
    return f"scrypt${_N}${_R}${_P}${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        _, n, r, p, salt, dk = stored.split("$")
        calc = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=int(n), r=int(r), p=int(p), dklen=32)
        return hmac.compare_digest(calc.hex(), dk)
    except (ValueError, TypeError):
        return False


# Verified against when the email is unknown, so response time does not reveal which emails exist.
_DUMMY = hash_password("not-a-real-password")


def burn_dummy_verify(password: str) -> None:
    verify_password(password, _DUMMY)


def new_token() -> tuple[str, str]:
    """Returns (token for the client, sha256 hash stored server-side)."""
    t = secrets.token_urlsafe(32)
    return t, hash_token(t)


def hash_token(t: str) -> str:
    return hashlib.sha256(t.encode()).hexdigest()


def expiry() -> datetime:
    return datetime.now(timezone.utc) + timedelta(hours=SESSION_HOURS)
