from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.base import BaseHTTPMiddleware

from app.api.events import router as events_router
from app.api.routes import router
from app.core.config import get_settings
from app.core.errors import http_exception_handler, validation_exception_handler
from app.core.ratelimit import rate_limit_middleware, request_size_middleware


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        description="Prompt injection detection and defense middleware for enterprise AI agents.",
    )

    # Attach settings to app state so middleware can access them
    app.state.settings = settings

    # CORS for the Next.js dashboard (localhost dev + Docker)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[
            "http://localhost:3000",
            "http://127.0.0.1:3000",
            "http://localhost:3100",
            "http://127.0.0.1:3100",
        ],
        allow_methods=["GET", "POST"],
        allow_headers=["*"],
    )

    # Middleware (outermost first)
    app.add_middleware(BaseHTTPMiddleware, dispatch=request_size_middleware)
    app.add_middleware(BaseHTTPMiddleware, dispatch=rate_limit_middleware)

    # Exception handlers
    app.add_exception_handler(StarletteHTTPException, http_exception_handler)
    app.add_exception_handler(RequestValidationError, validation_exception_handler)

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "service": settings.app_name, "version": settings.app_version}

    app.include_router(router)
    app.include_router(events_router)
    return app


app = create_app()
