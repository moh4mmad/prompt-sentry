from fastapi import Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException


async def http_exception_handler(request: Request, exc: StarletteHTTPException) -> JSONResponse:
    if isinstance(exc.detail, dict):
        body = exc.detail
    else:
        body = {
            "type": "https://promptsentry.dev/errors/http-error",
            "title": "HTTP Error",
            "status": exc.status_code,
            "detail": str(exc.detail),
        }
    return JSONResponse(status_code=exc.status_code, content=body, headers=exc.headers)


async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "type": "https://promptsentry.dev/errors/validation-error",
            "title": "Validation Error",
            "status": 422,
            "detail": "Request body failed schema validation.",
            "errors": exc.errors(),
        },
    )


async def request_too_large_handler(request: Request, exc: Exception) -> JSONResponse:
    return JSONResponse(
        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
        content={
            "type": "https://promptsentry.dev/errors/request-too-large",
            "title": "Request Too Large",
            "status": 413,
            "detail": "Request body exceeds the maximum allowed size.",
        },
    )
