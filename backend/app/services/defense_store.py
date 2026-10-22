from fastapi import HTTPException
from sqlalchemy import select, update
from sqlalchemy.orm import Session
from ..models import DefenseConfig
from .defenses import DefenseSettings


def get_active(db: Session) -> DefenseConfig | None:
    return db.scalar(select(DefenseConfig).where(DefenseConfig.is_active.is_(True)).order_by(DefenseConfig.id.desc()).limit(1))


def settings_of(c: DefenseConfig) -> DefenseSettings:
    return DefenseSettings(c.id, bool(c.input_validation), bool(c.hardened_prompt), bool(c.output_checking), c.policy_text or "")


def save_new_version(db: Session, *, name: str, input_screen: bool, hardened_prompt: bool, output_redaction: bool,
                     policy_text: str, user_id: int) -> DefenseConfig:
    """Configs are immutable versions: saving creates a new row and makes it the only active one."""
    db.execute(update(DefenseConfig).values(is_active=False))
    c = DefenseConfig(name=name, input_validation=input_screen, hardened_prompt=hardened_prompt,
                      output_checking=output_redaction, policy_text=policy_text, is_active=True, created_by=user_id)
    db.add(c)
    db.commit()
    db.refresh(c)
    return c


def resolve(db: Session, mode: str) -> tuple[str, DefenseSettings | None]:
    """mode: baseline | defended | auto -> (effective mode, settings or None)."""
    if mode == "baseline":
        return "baseline", None
    active = get_active(db)
    if active:
        return "defended", settings_of(active)
    if mode == "defended":
        raise HTTPException(status_code=409, detail="No defense configuration has been saved yet. A Blue Team user must save one first.")
    return "baseline", None  # auto with nothing configured
