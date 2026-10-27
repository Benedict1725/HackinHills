from datetime import datetime, timezone
from fastapi import APIRouter, Depends
from ..models import User
from ..services.auth import current_user
from ..ai.providers import ProviderError, build_provider
from ..config import get_settings
from ..schemas import AIHealthResponse

router = APIRouter(prefix="/api", tags=["ai"])


def get_provider_factory():
    """Dependency so tests can swap in a mock provider."""
    return build_provider


@router.get("/ai/health", response_model=AIHealthResponse)
def ai_health(factory=Depends(get_provider_factory), user: User = Depends(current_user)):
    s = get_settings()
    now = datetime.now(timezone.utc)
    try:
        h = factory().health()
        return AIHealthResponse(ok=h.ok, provider=h.provider, model=h.model or None, detail=h.detail, checked_at=now)
    except ProviderError as e:
        return AIHealthResponse(ok=False, provider=s.provider, model=s.model or None, detail=e.message, checked_at=now)
