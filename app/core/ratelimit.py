import hashlib
import ipaddress
import json
import time
from collections import defaultdict, deque
from typing import Any

from fastapi import HTTPException, Request, status
from starlette.types import ASGIApp, Message, Receive, Scope, Send

# Development fallback. Production configuration requires Redis.
_windows: dict[str, deque] = defaultdict(deque)
_redis_clients: dict[str, Any] = {}


class RequestSizeLimitMiddleware:
    """Enforce request size for both Content-Length and chunked bodies."""

    def __init__(self, app: ASGIApp, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = {key.lower(): value for key, value in scope.get("headers", [])}
        content_length = headers.get(b"content-length")
        if content_length:
            try:
                if int(content_length) > self.max_bytes:
                    await self._reject(send)
                    return
            except ValueError:
                await self._reject(send)
                return

        received = 0

        async def limited_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes:
                    raise _RequestTooLarge
            return message

        try:
            await self.app(scope, limited_receive, send)
        except _RequestTooLarge:
            await self._reject(send)

    @staticmethod
    async def _reject(send: Send) -> None:
        body = json.dumps(
            {
                "type": "https://promptsentry.dev/errors/request-too-large",
                "title": "Request Too Large",
                "status": 413,
                "detail": "Request body exceeds the maximum allowed size.",
            }
        ).encode()
        await send(
            {
                "type": "http.response.start",
                "status": 413,
                "headers": [
                    (b"content-type", b"application/problem+json"),
                    (b"content-length", str(len(body)).encode()),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})


class _RequestTooLarge(Exception):
    pass


def _client_key(request: Request) -> str:
    api_key = request.headers.get("X-API-Key") or request.headers.get("X-Dashboard-Key")
    if api_key:
        return "key:" + hashlib.sha256(api_key.encode()).hexdigest()[:24]

    peer = request.client.host if request.client else "unknown"
    client_ip = peer
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for and _is_trusted_proxy(peer, request.app.state.settings.trusted_proxy_cidrs):
        client_ip = (
            _untrusted_forwarded_address(forwarded_for, request.app.state.settings.trusted_proxy_cidrs) or peer
        )
    return "ip:" + client_ip


def _is_trusted_proxy(peer: str, configured_cidrs: str) -> bool:
    if not configured_cidrs:
        return False
    try:
        address = ipaddress.ip_address(peer)
    except ValueError:
        return False
    for value in configured_cidrs.split(","):
        try:
            if address in ipaddress.ip_network(value.strip(), strict=False):
                return True
        except ValueError:
            continue
    return False


def _untrusted_forwarded_address(forwarded_for: str, configured_cidrs: str) -> str | None:
    networks = []
    for value in configured_cidrs.split(","):
        try:
            networks.append(ipaddress.ip_network(value.strip(), strict=False))
        except ValueError:
            continue
    addresses = []
    for value in forwarded_for.split(","):
        try:
            addresses.append(ipaddress.ip_address(value.strip()))
        except ValueError:
            return None
    for address in reversed(addresses):
        if not any(address in network for network in networks):
            return str(address)
    return str(addresses[0]) if addresses else None


async def rate_limit_middleware(request: Request, call_next):
    if request.url.path == "/health":
        return await call_next(request)

    settings = request.app.state.settings
    limit = settings.rate_limit_per_minute
    key = _client_key(request)
    if settings.rate_limit_backend == "redis":
        try:
            count = await _increment_redis(settings.redis_url, key)
        except Exception as exc:
            if settings.rate_limit_fail_open:
                return await call_next(request)
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={
                    "type": "https://promptsentry.dev/errors/rate-limiter-unavailable",
                    "title": "Service Unavailable",
                    "status": 503,
                    "detail": "Rate limiting service is unavailable.",
                },
            ) from exc
        if count > limit:
            _raise_rate_limited(limit)
        return await call_next(request)

    now = time.monotonic()
    window = _windows[key]

    # Drop entries older than 60 s
    while window and now - window[0] > 60.0:
        window.popleft()

    if len(window) >= limit:
        _raise_rate_limited(limit)

    window.append(now)
    return await call_next(request)


async def _increment_redis(redis_url: str | None, key: str) -> int:
    if not redis_url:
        raise RuntimeError("REDIS_URL is required for Redis rate limiting")
    client = _redis_clients.get(redis_url)
    if client is None:
        try:
            from redis.asyncio import from_url
        except ImportError as exc:  # pragma: no cover - configuration error
            raise RuntimeError("Install the 'production' extra to use Redis") from exc
        client = from_url(redis_url, encoding="utf-8", decode_responses=True)
        _redis_clients[redis_url] = client
    bucket = int(time.time() // 60)
    redis_key = f"prompt-sentry:rate:{bucket}:{key}"
    result = await client.eval(
        "local n=redis.call('INCR',KEYS[1]); "
        "if n==1 then redis.call('EXPIRE',KEYS[1],ARGV[1]) end; return n",
        1,
        redis_key,
        120,
    )
    return int(result)


async def redis_is_ready(redis_url: str | None) -> bool:
    if not redis_url:
        return False
    try:
        client = _redis_clients.get(redis_url)
        if client is None:
            from redis.asyncio import from_url

            client = from_url(redis_url, encoding="utf-8", decode_responses=True)
            _redis_clients[redis_url] = client
        return bool(await client.ping())
    except Exception:
        return False


async def close_redis_clients() -> None:
    for client in _redis_clients.values():
        await client.aclose()
    _redis_clients.clear()


def _raise_rate_limited(limit: int) -> None:
    raise HTTPException(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        detail={
            "type": "https://promptsentry.dev/errors/rate-limit-exceeded",
            "title": "Rate Limit Exceeded",
            "status": 429,
            "detail": f"Maximum {limit} requests per minute.",
        },
        headers={"Retry-After": "60"},
    )


async def request_size_middleware(request: Request, call_next):
    settings = request.app.state.settings
    content_length = request.headers.get("content-length")
    try:
        too_large = bool(content_length) and int(content_length) > settings.max_request_bytes
    except ValueError:
        too_large = True
    if too_large:
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
