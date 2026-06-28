from __future__ import annotations

import os
from typing import Any
from uuid import uuid4

import httpx

from prompt_sentry.exceptions import PromptSentryBlocked, PromptSentryUnavailable, json_safe, safe_tool_error
from prompt_sentry.models import Action, InspectionResult, SecurityContext, ToolReviewResult


class _ClientConfig:
    def __init__(
        self,
        *,
        base_url: str | None,
        api_key: str | None,
        timeout: float,
        fail_open: bool,
        max_retries: int,
    ) -> None:
        self.base_url = (base_url or os.getenv("PROMPT_SENTRY_URL") or "http://localhost:8100").rstrip("/")
        self.api_key = api_key if api_key is not None else os.getenv("PROMPT_SENTRY_API_KEY")
        self.timeout = timeout
        self.fail_open = fail_open
        self.max_retries = max(0, max_retries)

    @property
    def headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["X-API-Key"] = self.api_key
        return headers


class _ResultParser:
    @staticmethod
    def inspection(data: dict[str, Any]) -> InspectionResult:
        return InspectionResult(
            request_id=str(data["request_id"]),
            action=Action(data["action"]),
            risk_score=float(data["risk_score"]),
            severity=str(data["severity"]),
            sanitized_text=data.get("sanitized_text"),
            findings=tuple(data.get("findings", ())),
            audit_event_id=data.get("audit_event_id"),
        )

    @staticmethod
    def tool(data: dict[str, Any]) -> ToolReviewResult:
        return ToolReviewResult(
            request_id=str(data["request_id"]),
            action=Action(data["action"]),
            risk_score=float(data["risk_score"]),
            severity=str(data["severity"]),
            reason=str(data.get("reason", "Tool call denied by security policy.")),
            findings=tuple(data.get("findings", ())),
            audit_event_id=data.get("audit_event_id"),
        )


def _security_payload(text: str, source: str, context: SecurityContext, request_id: str) -> dict[str, Any]:
    return {
        "request_id": request_id,
        "tenant_id": context.tenant_id,
        "user_id": context.user_id,
        "session_id": context.session_id,
        "source": source,
        "text": text,
        "metadata": context.request_metadata(),
    }


def _tool_payload(
    tool_name: str,
    arguments: dict[str, Any],
    context: SecurityContext,
    request_id: str,
) -> dict[str, Any]:
    metadata = context.request_metadata()
    metadata["allowed_tools"] = list(context.allowed_tools)
    metadata["allowed_data_scopes"] = list(context.allowed_data_scopes)
    return {
        "request_id": request_id,
        "tenant_id": context.tenant_id,
        "user_id": context.user_id,
        "session_id": context.session_id,
        "tool_name": tool_name,
        "arguments": arguments,
        "metadata": metadata,
    }


def _raise_blocked(result: InspectionResult | ToolReviewResult) -> None:
    findings = tuple(str(item.get("attack_type", "unknown")) for item in result.findings)
    raise PromptSentryBlocked(
        action=result.action.value,
        risk_score=result.risk_score,
        attack_types=findings,
        reason=getattr(result, "reason", None),
        request_id=result.request_id,
    )


class PromptSentryClient:
    def __init__(
        self,
        *,
        base_url: str | None = None,
        api_key: str | None = None,
        timeout: float = 5.0,
        fail_open: bool = False,
        max_retries: int = 0,
        http_client: httpx.Client | None = None,
    ) -> None:
        self.config = _ClientConfig(
            base_url=base_url,
            api_key=api_key,
            timeout=timeout,
            fail_open=fail_open,
            max_retries=max_retries,
        )
        self._http = http_client or httpx.Client(
            timeout=timeout,
            transport=httpx.HTTPTransport(retries=self.config.max_retries),
        )
        self._owns_http = http_client is None

    def close(self) -> None:
        if self._owns_http:
            self._http.close()

    def __enter__(self) -> PromptSentryClient:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def inspect(
        self,
        text: str,
        *,
        source: str,
        context: SecurityContext | None = None,
        request_id: str | None = None,
        verify_output: bool = False,
    ) -> InspectionResult:
        context = context or SecurityContext()
        request_id = request_id or f"sdk_{uuid4().hex}"
        path = "/v1/verify-output" if verify_output else "/v1/inspect"
        try:
            response = self._http.post(
                self.config.base_url + path,
                json=_security_payload(text, source, context, request_id),
                headers=self.config.headers,
                timeout=self.config.timeout,
            )
            response.raise_for_status()
            return _ResultParser.inspection(response.json())
        except (httpx.HTTPError, KeyError, TypeError, ValueError) as exc:
            if self.config.fail_open and _may_fail_open(exc):
                return InspectionResult(request_id, Action.ALLOW, 0.0, "low", text)
            raise PromptSentryUnavailable("PromptSentry could not return an inspection decision") from exc

    def protect_text(self, text: str, *, source: str, context: SecurityContext | None = None) -> str:
        result = self.inspect(text, source=source, context=context)
        if result.denied:
            _raise_blocked(result)
        return result.sanitized_text if result.action == Action.SANITIZE and result.sanitized_text is not None else text

    def verify_output(self, text: str, *, context: SecurityContext | None = None) -> str:
        result = self.inspect(text, source="model_output", context=context, verify_output=True)
        if result.denied:
            _raise_blocked(result)
        return result.sanitized_text if result.action == Action.SANITIZE and result.sanitized_text is not None else text

    def review_tool_call(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        *,
        context: SecurityContext | None = None,
        request_id: str | None = None,
    ) -> ToolReviewResult:
        context = context or SecurityContext()
        request_id = request_id or f"tool_{uuid4().hex}"
        try:
            response = self._http.post(
                self.config.base_url + "/v1/review-tool-call",
                json=_tool_payload(tool_name, arguments, context, request_id),
                headers=self.config.headers,
                timeout=self.config.timeout,
            )
            response.raise_for_status()
            return _ResultParser.tool(response.json())
        except (httpx.HTTPError, KeyError, TypeError, ValueError) as exc:
            if self.config.fail_open and _may_fail_open(exc):
                return ToolReviewResult(request_id, Action.ALLOW, 0.0, "low", "Fail-open development mode.")
            raise PromptSentryUnavailable("PromptSentry could not return a tool decision") from exc

    def protect_tool_output(self, value: Any, *, context: SecurityContext | None = None) -> str:
        serialized = json_safe(value)
        result = self.inspect(serialized, source="tool_output", context=context)
        if result.denied:
            return safe_tool_error("Tool output was blocked by PromptSentry")
        if result.action == Action.SANITIZE:
            if isinstance(value, str) and result.sanitized_text is not None:
                return result.sanitized_text
            return safe_tool_error("Structured tool output could not be safely sanitized")
        return serialized


class AsyncPromptSentryClient:
    def __init__(
        self,
        *,
        base_url: str | None = None,
        api_key: str | None = None,
        timeout: float = 5.0,
        fail_open: bool = False,
        max_retries: int = 0,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self.config = _ClientConfig(
            base_url=base_url,
            api_key=api_key,
            timeout=timeout,
            fail_open=fail_open,
            max_retries=max_retries,
        )
        self._http = http_client or httpx.AsyncClient(
            timeout=timeout,
            transport=httpx.AsyncHTTPTransport(retries=self.config.max_retries),
        )
        self._owns_http = http_client is None

    async def aclose(self) -> None:
        if self._owns_http:
            await self._http.aclose()

    async def __aenter__(self) -> AsyncPromptSentryClient:
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.aclose()

    async def inspect(
        self,
        text: str,
        *,
        source: str,
        context: SecurityContext | None = None,
        request_id: str | None = None,
        verify_output: bool = False,
    ) -> InspectionResult:
        context = context or SecurityContext()
        request_id = request_id or f"sdk_{uuid4().hex}"
        path = "/v1/verify-output" if verify_output else "/v1/inspect"
        try:
            response = await self._http.post(
                self.config.base_url + path,
                json=_security_payload(text, source, context, request_id),
                headers=self.config.headers,
                timeout=self.config.timeout,
            )
            response.raise_for_status()
            return _ResultParser.inspection(response.json())
        except (httpx.HTTPError, KeyError, TypeError, ValueError) as exc:
            if self.config.fail_open and _may_fail_open(exc):
                return InspectionResult(request_id, Action.ALLOW, 0.0, "low", text)
            raise PromptSentryUnavailable("PromptSentry could not return an inspection decision") from exc

    async def protect_text(self, text: str, *, source: str, context: SecurityContext | None = None) -> str:
        result = await self.inspect(text, source=source, context=context)
        if result.denied:
            _raise_blocked(result)
        return result.sanitized_text if result.action == Action.SANITIZE and result.sanitized_text is not None else text

    async def verify_output(self, text: str, *, context: SecurityContext | None = None) -> str:
        result = await self.inspect(text, source="model_output", context=context, verify_output=True)
        if result.denied:
            _raise_blocked(result)
        return result.sanitized_text if result.action == Action.SANITIZE and result.sanitized_text is not None else text

    async def review_tool_call(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        *,
        context: SecurityContext | None = None,
        request_id: str | None = None,
    ) -> ToolReviewResult:
        context = context or SecurityContext()
        request_id = request_id or f"tool_{uuid4().hex}"
        try:
            response = await self._http.post(
                self.config.base_url + "/v1/review-tool-call",
                json=_tool_payload(tool_name, arguments, context, request_id),
                headers=self.config.headers,
                timeout=self.config.timeout,
            )
            response.raise_for_status()
            return _ResultParser.tool(response.json())
        except (httpx.HTTPError, KeyError, TypeError, ValueError) as exc:
            if self.config.fail_open and _may_fail_open(exc):
                return ToolReviewResult(request_id, Action.ALLOW, 0.0, "low", "Fail-open development mode.")
            raise PromptSentryUnavailable("PromptSentry could not return a tool decision") from exc

    async def protect_tool_output(self, value: Any, *, context: SecurityContext | None = None) -> str:
        serialized = json_safe(value)
        result = await self.inspect(serialized, source="tool_output", context=context)
        if result.denied:
            return safe_tool_error("Tool output was blocked by PromptSentry")
        if result.action == Action.SANITIZE:
            if isinstance(value, str) and result.sanitized_text is not None:
                return result.sanitized_text
            return safe_tool_error("Structured tool output could not be safely sanitized")
        return serialized


def _may_fail_open(error: Exception) -> bool:
    if isinstance(error, (httpx.ConnectError, httpx.TimeoutException)):
        return True
    return isinstance(error, httpx.HTTPStatusError) and error.response.status_code >= 500
