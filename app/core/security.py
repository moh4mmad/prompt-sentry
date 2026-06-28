import secrets

from fastapi import HTTPException, Request, Security, status
from fastapi.security import APIKeyHeader

from app.core.config import Settings

_API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)
_DASHBOARD_KEY_HEADER = APIKeyHeader(name="X-Dashboard-Key", auto_error=False)


def require_api_key(
    request: Request,
    api_key_header: str | None = Security(_API_KEY_HEADER),
) -> None:
    settings: Settings = request.app.state.settings
    if settings.api_key is None:
        return
    if api_key_header is None or not secrets.compare_digest(api_key_header, settings.api_key):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "type": "https://promptsentry.dev/errors/unauthorized",
                "title": "Unauthorized",
                "status": 401,
                "detail": "Missing or invalid X-API-Key header.",
            },
        )


def require_dashboard_api_key(
    request: Request,
    dashboard_key_header: str | None = Security(_DASHBOARD_KEY_HEADER),
) -> None:
    settings: Settings = request.app.state.settings
    if settings.dashboard_api_key is None:
        return
    if dashboard_key_header is None or not secrets.compare_digest(dashboard_key_header, settings.dashboard_api_key):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "type": "https://promptsentry.dev/errors/unauthorized",
                "title": "Unauthorized",
                "status": 401,
                "detail": "Missing or invalid X-Dashboard-Key header.",
            },
        )
