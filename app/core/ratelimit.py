import time
from collections import defaultdict, deque

from fastapi import HTTPException, Request, status

# In-memory sliding-window rate limiter (no Redis dependency for MVP; swap for Redis in enterprise tier)
_windows: dict[str, deque] = defaultdict(deque)


def _client_key(request: Request) -> str:
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


async def rate_limit_middleware(request: Request, call_next):
    if request.url.path == "/health":
        return await call_next(request)

    settings = request.app.state.settings
    limit = settings.rate_limit_per_minute
    key = _client_key(request)
    now = time.monotonic()
    window = _windows[key]

    # Drop entries older than 60 s
    while window and now - window[0] > 60.0:
        window.popleft()

    if len(window) >= limit:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={
                "type": "https://promptsentry.dev/errors/rate-limit-exceeded",
                "title": "Rate Limit Exceeded",
                "status": 429,
                "detail": f"Maximum {limit} requests per minute.",
            },
        )

    window.append(now)
    return await call_next(request)


async def request_size_middleware(request: Request, call_next):
    settings = request.app.state.settings
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > settings.max_request_bytes:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail={
                "type": "https://promptsentry.dev/errors/request-too-large",
                "title": "Request Too Large",
                "status": 413,
                "detail": "Request body exceeds the maximum allowed size.",
            },
        )
    return await call_next(request)
