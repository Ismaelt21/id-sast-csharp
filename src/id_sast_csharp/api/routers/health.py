from fastapi import APIRouter

from id_sast_csharp.api.schemas.common import MessageResponse
from id_sast_csharp.infrastructure.config.settings import Settings

router = APIRouter(prefix="/health", tags=["health"])


@router.get("", response_model=MessageResponse)
def health() -> MessageResponse:
    return MessageResponse(message=f"ok:{Settings.APP_NAME}")

