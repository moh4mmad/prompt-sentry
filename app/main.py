from contextlib import asynccontextmanager

from fastapi import FastAPI, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.base import BaseHTTPMiddleware

from app.api.events import router as events_router
from app.api.routes import router
from app.core.config import get_settings
from app.core.errors import http_exception_handler, validation_exception_handler
from app.core.headers import SecurityHeadersMiddleware
from app.core.ratelimit import (
    RequestSizeLimitMiddleware,
    close_redis_clients,
    rate_limit_middleware,
    redis_is_ready,
)
from app.logging.audit import AuditLogger, close_postgres_pools


def create_app() -> FastAPI:
    settings = get_settings()

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        AuditLogger(settings).ensure_schema()
        try:
            yield
        finally:
            await close_redis_clients()
            close_postgres_pools()

    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        description="Prompt injection detection and defense middleware for enterprise AI agents.",
        lifespan=lifespan,
        docs_url="/docs" if settings.docs_enabled else None,
        redoc_url="/redoc" if settings.docs_enabled else None,
        openapi_url="/openapi.json" if settings.docs_enabled else None,
    )

    # Attach settings to app state so middleware can access them
    app.state.settings = settings

    # CORS for the Next.js dashboard (localhost dev + Docker)
    if settings.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_origins,
            allow_methods=["GET", "POST"],
            allow_headers=["Content-Type", "X-API-Key", "X-Dashboard-Key"],
        )

    # Starlette applies the last-added middleware first.
    app.add_middleware(BaseHTTPMiddleware, dispatch=rate_limit_middleware)
    app.add_middleware(RequestSizeLimitMiddleware, max_bytes=settings.max_request_bytes)
    app.add_middleware(SecurityHeadersMiddleware, enable_hsts=settings.enable_hsts)

    # Exception handlers
    app.add_exception_handler(StarletteHTTPException, http_exception_handler)
    app.add_exception_handler(RequestValidationError, validation_exception_handler)

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "service": settings.app_name, "version": settings.app_version}

    @app.get("/ready")
    async def ready() -> JSONResponse:
        audit_ready = AuditLogger(settings).is_ready()
        rate_limit_ready = (
            await redis_is_ready(settings.redis_url) if settings.rate_limit_backend == "redis" else True
        )
        ready_now = audit_ready and rate_limit_ready
        return JSONResponse(
            status_code=status.HTTP_200_OK if ready_now else status.HTTP_503_SERVICE_UNAVAILABLE,
            content={
                "status": "ready" if ready_now else "not_ready",
                "dependencies": {"audit": audit_ready, "rate_limit": rate_limit_ready},
            },
        )

    app.include_router(router)
    app.include_router(events_router)
    return app


app = create_app()
