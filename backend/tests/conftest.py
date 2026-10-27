import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.ai.providers import Provider, ProviderError, ProviderHealth
from app.database import Base, get_db
from app.main import app
from app.models import AuthSession, User
from app.routes.ai import get_provider_factory
from app.services import auth as auth_svc
from app.services.security import expiry, hash_password, new_token

PASSWORD = "correct-horse-battery"


class FakeProvider(Provider):
    name, model = "mock", "mock-1"

    def __init__(self, reply="OK", error=None, healthy=True):
        self.reply, self.error, self.healthy, self.calls, self.systems = reply, error, healthy, 0, []

    def health(self):
        return ProviderHealth(self.healthy, self.name, self.model, "mock health" if self.healthy else "mock is down")

    def generate(self, system, user):
        self.calls += 1
        self.systems.append(system)
        if self.error:
            raise self.error
        return self.reply(system, user) if callable(self.reply) else self.reply


@pytest.fixture()
def env(tmp_path):
    """(client, holder, Session, engine). The client is signed in as Red Team by default.
    holder['hdr'][role] gives Authorization headers for red_team / blue_team / admin."""
    from app import models  # noqa: F401
    engine = create_engine(f"sqlite:///{tmp_path/'t.db'}", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, autoflush=False)

    def _db():
        db = Session()
        try:
            yield db
        finally:
            db.close()

    hdr = {}
    with Session() as db:
        ph = hash_password(PASSWORD)
        for role in ("red_team", "blue_team", "admin"):
            u = User(email=f"{role}@test.local", role=role, password_hash=ph)
            db.add(u); db.commit()
            tok, th = new_token()
            db.add(AuthSession(token_hash=th, user_id=u.id, expires_at=expiry())); db.commit()
            hdr[role] = {"Authorization": f"Bearer {tok}"}

    holder = {"provider": FakeProvider(), "hdr": hdr}
    app.dependency_overrides[get_db] = _db
    app.dependency_overrides[get_provider_factory] = lambda: (lambda: holder["provider"])
    auth_svc._fails.clear()
    client = TestClient(app, raise_server_exceptions=False, headers=hdr["red_team"])
    yield client, holder, Session, engine
    app.dependency_overrides.clear()


def audit_rows(Session):
    from sqlalchemy import select
    from app.models import AuditEvent
    with Session() as db:
        return db.scalars(select(AuditEvent).order_by(AuditEvent.id)).all()
