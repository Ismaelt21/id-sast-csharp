from fastapi import APIRouter

router = APIRouter(prefix="/version", tags=["version"])


@router.get("")
def version() -> dict:
    from id_sast_csharp.infrastructure.config.settings import Settings

    return {
        "service": Settings.APP_NAME,
        "version": Settings.VERSION,
        "environment": Settings.ENVIRONMENT,
        "features": {
            "ai": Settings.USE_GEMINI,
            "persistence": Settings.USE_PERSISTENCE,
        },
    }

