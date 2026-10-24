from datetime import datetime, timezone
from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column
from .database import Base


def utcnow():
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    # Only a salted hash is ever stored. Auth is implemented in a later phase.
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(32), default="analyst")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AuthSession(Base):
    __tablename__ = "sessions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)  # SHA-256 of the bearer token
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class DefenseConfig(Base):
    __tablename__ = "defense_configs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(100), default="default")
    # Column names kept from Day 1. input_validation = injection/jailbreak input screen,
    # output_checking = protected-secret output redaction.
    input_validation: Mapped[bool] = mapped_column(Boolean, default=True)
    output_checking: Mapped[bool] = mapped_column(Boolean, default=True)
    hardened_prompt: Mapped[bool] = mapped_column(Boolean, default=True)
    # Enforces explicit response-format contracts from trusted system instructions.
    output_contract: Mapped[bool] = mapped_column(Boolean, default=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=False)
    policy_text: Mapped[str] = mapped_column(Text, default="")
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class TestRun(Base):
    __test__ = False  # not a pytest class
    __tablename__ = "test_runs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    test_id: Mapped[str | None] = mapped_column(String(32), unique=True, index=True, nullable=True)
    test_case_id: Mapped[str | None] = mapped_column(String(32), nullable=True)  # None = custom test
    test_name: Mapped[str | None] = mapped_column(String(200), nullable=True)
    provider: Mapped[str | None] = mapped_column(String(32), nullable=True)
    explanation: Mapped[str | None] = mapped_column(Text, nullable=True)
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    owner_role: Mapped[str | None] = mapped_column(String(16), nullable=True)  # red_team | blue_team (None = legacy, admin-only)
    run_group_id: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    comparison_id: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)  # links a baseline+defended pair
    defense_triggered: Mapped[bool] = mapped_column(Boolean, default=False)
    defense_actions: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON list, e.g. ["input_screen:blocked"]
    test_suite_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    trial_number: Mapped[int] = mapped_column(Integer, default=1)
    model_digest: Mapped[str | None] = mapped_column(String(255), nullable=True)
    human_review_status: Mapped[str | None] = mapped_column(String(16), nullable=True)
    category: Mapped[str] = mapped_column(String(64))
    prompt: Mapped[str] = mapped_column(Text)
    model: Mapped[str | None] = mapped_column(String(100), nullable=True)
    mode: Mapped[str] = mapped_column(String(16), default="baseline")  # baseline | defended
    response: Mapped[str | None] = mapped_column(Text, nullable=True)
    outcome: Mapped[str] = mapped_column(String(16), default="NEEDS_REVIEW")  # PASS | FAIL | NEEDS_REVIEW | ERROR
    is_demo: Mapped[bool] = mapped_column(Boolean, default=False)
    defense_config_id: Mapped[int | None] = mapped_column(ForeignKey("defense_configs.id"), nullable=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AuditEvent(Base):
    __tablename__ = "audit_events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ts: Mapped[str | None] = mapped_column(String(40), nullable=True)  # ISO string, hashed as-is
    test_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    prev_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    event_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    action: Mapped[str] = mapped_column(String(100))
    actor: Mapped[str] = mapped_column(String(100), default="system")
    status: Mapped[str] = mapped_column(String(16), default="success")
    details: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
