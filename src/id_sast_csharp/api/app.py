from fastapi import FastAPI

from id_sast_csharp.api.routers.analysis import router as analysis_router
from id_sast_csharp.api.routers.health import router as health_router
from id_sast_csharp.api.routers.rules import router as rules_router
from id_sast_csharp.api.routers.scan import router as scan_router
from id_sast_csharp.api.routers.version import router as version_router
from id_sast_csharp.infrastructure.config.settings import Settings


def create_app() -> FastAPI:
    Settings.initialize_directories()

    app = FastAPI(
        title=Settings.APP_NAME,
        version=Settings.VERSION,
        description="ID-SAST C# microservice",
    )

    app.include_router(health_router)
    app.include_router(version_router)
    app.include_router(scan_router)
    app.include_router(rules_router)
    app.include_router(analysis_router)

    return app


app = create_app()

