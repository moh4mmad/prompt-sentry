from __future__ import annotations

import inspect
from collections.abc import Awaitable, Callable, Mapping
from contextlib import AsyncExitStack
from functools import wraps
from typing import Any, Protocol

from prompt_sentry.client import AsyncPromptSentryClient, PromptSentryClient
from prompt_sentry.exceptions import json_safe, safe_tool_error
from prompt_sentry.models import SecurityContext


class MCPUpstream(Protocol):
    async def list_tools(self) -> Any: ...

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> Any: ...


class ProtectedFastMCP:
    """Wrap a stable FastMCP v1 server so every owned tool is protected."""

    def __init__(
        self,
        server: Any,
        sentry: PromptSentryClient | AsyncPromptSentryClient,
        context: SecurityContext | None = None,
    ) -> None:
        self.server = server
        self.sentry = sentry
        self.context = (context or SecurityContext()).with_updates(framework="mcp")

    def __getattr__(self, name: str) -> Any:
        return getattr(self.server, name)

    def tool(self, *decorator_args: Any, **decorator_kwargs: Any) -> Callable[[Callable[..., Any]], Any]:
        def register(function: Callable[..., Any]) -> Any:
            name = str(decorator_kwargs.get("name") or function.__name__)
            protected = self._protect(function, name)
            return self.server.tool(*decorator_args, **decorator_kwargs)(protected)

        return register

    def _protect(self, function: Callable[..., Any], name: str) -> Callable[..., Any]:
        if inspect.iscoroutinefunction(function):

            @wraps(function)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                arguments = _serializable_arguments(kwargs)
                context = self.context.with_updates(tool_call_id=_request_id(kwargs))
                review = await _maybe_await(self.sentry.review_tool_call(name, arguments, context=context))
                if review.denied:
                    return safe_tool_error(review.reason)
                result = await function(*args, **kwargs)
                return await _maybe_await(self.sentry.protect_tool_output(result, context=context))

            return async_wrapper

        @wraps(function)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            if isinstance(self.sentry, AsyncPromptSentryClient):
                raise TypeError("AsyncPromptSentryClient requires async MCP tool functions")
            arguments = _serializable_arguments(kwargs)
            context = self.context.with_updates(tool_call_id=_request_id(kwargs))
            review = self.sentry.review_tool_call(name, arguments, context=context)
            if review.denied:
                return safe_tool_error(review.reason)
            return self.sentry.protect_tool_output(function(*args, **kwargs), context=context)

        return sync_wrapper


class PromptSentryMCPGateway:
    """Policy gateway for arbitrary upstream MCP servers."""

    def __init__(
        self,
        upstream: MCPUpstream,
        sentry: AsyncPromptSentryClient,
        context: SecurityContext | None = None,
    ) -> None:
        self.upstream = upstream
        self.sentry = sentry
        self.context = (context or SecurityContext()).with_updates(framework="mcp_gateway")

    async def list_tools(self) -> list[Any]:
        response = await self.upstream.list_tools()
        tools = list(getattr(response, "tools", response))
        allowed = set(self.context.allowed_tools)
        return [tool for tool in tools if not allowed or _value(tool, "name") in allowed]

    async def call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> Any:
        arguments = arguments or {}
        allowed = set(self.context.allowed_tools)
        if allowed and name not in allowed:
            return _mcp_error(f"Tool '{name}' is not authorized")
        review = await self.sentry.review_tool_call(name, arguments, context=self.context)
        if review.denied:
            return _mcp_error(review.reason)
        result = await self.upstream.call_tool(name, arguments)
        original = _result_payload(result)
        protected = await self.sentry.protect_tool_output(original, context=self.context)
        if _looks_denied(protected):
            return _mcp_error("Upstream tool output was blocked by PromptSentry")
        if protected != original:
            return _mcp_text_result(protected)
        return result


class StdioMCPUpstream:
    def __init__(self, command: str, args: list[str] | None = None, env: Mapping[str, str] | None = None) -> None:
        self.command = command
        self.args = args or []
        self.env = dict(env or {})
        self._stack: AsyncExitStack | None = None
        self._session: Any = None

    async def __aenter__(self) -> StdioMCPUpstream:
        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client

        self._stack = AsyncExitStack()
        params = StdioServerParameters(command=self.command, args=self.args, env=self.env or None)
        read, write = await self._stack.enter_async_context(stdio_client(params))
        self._session = await self._stack.enter_async_context(ClientSession(read, write))
        await self._session.initialize()
        return self

    async def __aexit__(self, *exc: object) -> None:
        if self._stack:
            await self._stack.aclose()

    async def list_tools(self) -> Any:
        return await self._required_session().list_tools()

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> Any:
        return await self._required_session().call_tool(name, arguments)

    def _required_session(self) -> Any:
        if self._session is None:
            raise RuntimeError("Use StdioMCPUpstream as an async context manager")
        return self._session


class StreamableHTTPMCPUpstream:
    """Connect to an upstream URL with service credentials, never caller tokens."""

    def __init__(self, url: str, headers: Mapping[str, str] | None = None) -> None:
        self.url = url
        self.headers = dict(headers or {})
        self._stack: AsyncExitStack | None = None
        self._session: Any = None

    async def __aenter__(self) -> StreamableHTTPMCPUpstream:
        import httpx
        from mcp import ClientSession
        from mcp.client.streamable_http import streamable_http_client

        self._stack = AsyncExitStack()
        http_client = await self._stack.enter_async_context(httpx.AsyncClient(headers=self.headers))
        streams = await self._stack.enter_async_context(
            streamable_http_client(self.url, http_client=http_client)
        )
        read, write = streams[0], streams[1]
        self._session = await self._stack.enter_async_context(ClientSession(read, write))
        await self._session.initialize()
        return self

    async def __aexit__(self, *exc: object) -> None:
        if self._stack:
            await self._stack.aclose()

    async def list_tools(self) -> Any:
        return await self._required_session().list_tools()

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> Any:
        return await self._required_session().call_tool(name, arguments)

    def _required_session(self) -> Any:
        if self._session is None:
            raise RuntimeError("Use StreamableHTTPMCPUpstream as an async context manager")
        return self._session


def create_gateway_server(gateway: PromptSentryMCPGateway, name: str = "PromptSentry MCP Gateway") -> Any:
    from mcp.server import Server

    server = Server(name)

    @server.list_tools()
    async def list_tools() -> list[Any]:
        return await gateway.list_tools()

    @server.call_tool()
    async def call_tool(tool_name: str, arguments: dict[str, Any]) -> Any:
        return await gateway.call_tool(tool_name, arguments)

    return server


async def _maybe_await(value: Any) -> Any:
    return await value if isinstance(value, Awaitable) else value


def _serializable_arguments(arguments: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in arguments.items() if value.__class__.__name__ != "Context"}


def _request_id(arguments: dict[str, Any]) -> str | None:
    for value in arguments.values():
        if value.__class__.__name__ == "Context":
            return str(getattr(value, "request_id", "")) or None
    return None


def _value(value: Any, key: str) -> Any:
    return value.get(key) if isinstance(value, dict) else getattr(value, key)


def _result_payload(result: Any) -> str:
    structured = getattr(result, "structuredContent", None)
    if structured is not None:
        return json_safe(structured)
    content = getattr(result, "content", result)
    if isinstance(content, list):
        return "\n".join(str(_value(item, "text")) for item in content if _value(item, "type") == "text")
    return json_safe(content)


def _looks_denied(value: str) -> bool:
    return '"ok":false' in value.replace(" ", "").lower()


def _mcp_error(message: str) -> Any:
    try:
        from mcp.types import CallToolResult, TextContent

        return CallToolResult(content=[TextContent(type="text", text=safe_tool_error(message))], isError=True)
    except ImportError:
        return {"content": [{"type": "text", "text": safe_tool_error(message)}], "isError": True}


def _mcp_text_result(text: str) -> Any:
    try:
        from mcp.types import CallToolResult, TextContent

        return CallToolResult(content=[TextContent(type="text", text=text)], isError=False)
    except ImportError:
        return {"content": [{"type": "text", "text": text}], "isError": False}
