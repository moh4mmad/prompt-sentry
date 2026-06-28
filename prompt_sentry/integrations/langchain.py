from __future__ import annotations

from dataclasses import replace
from typing import Any

from prompt_sentry.client import AsyncPromptSentryClient, PromptSentryClient
from prompt_sentry.exceptions import safe_tool_error
from prompt_sentry.models import SecurityContext

try:
    from langchain.agents.middleware import AgentMiddleware
    from langchain.messages import ToolMessage
except ImportError:  # pragma: no cover - exercised by optional dependency smoke tests
    AgentMiddleware = object  # type: ignore[assignment,misc]
    ToolMessage = None  # type: ignore[assignment,misc]


class PromptSentryMiddleware(AgentMiddleware):  # type: ignore[misc]
    """LangChain v1 middleware protecting model and tool boundaries."""

    def __init__(self, sentry: PromptSentryClient, context: SecurityContext | None = None) -> None:
        if ToolMessage is None:
            raise ImportError("Install prompt-sentry[langchain] to use PromptSentryMiddleware")
        self.sentry = sentry
        self.context = (context or SecurityContext()).with_updates(framework="langchain")

    def wrap_model_call(self, request: Any, handler: Any) -> Any:
        messages = list(request.messages)
        for index in range(len(messages) - 1, -1, -1):
            message = messages[index]
            if _message_role(message) in {"human", "user"}:
                safe = self.sentry.protect_text(_message_text(message), source="user_prompt", context=self.context)
                messages[index] = _replace_content(message, safe)
                request = request.override(messages=messages)
                break
        return handler(request)

    def wrap_tool_call(self, request: Any, handler: Any) -> Any:
        call = request.tool_call
        name = str(call["name"])
        arguments = dict(call.get("args", {}))
        call_id = str(call.get("id", "unknown"))
        context = self.context.with_updates(tool_call_id=call_id)
        review = self.sentry.review_tool_call(name, arguments, context=context)
        if review.denied:
            return ToolMessage(content=safe_tool_error(review.reason), tool_call_id=call_id, name=name, status="error")
        result = handler(request)
        return _protect_tool_result(result, self.sentry, context)

    def after_model(self, state: Any, runtime: Any) -> dict[str, Any] | None:
        del runtime
        messages = list(state.get("messages", ()))
        if not messages:
            return None
        message = messages[-1]
        if _message_role(message) not in {"ai", "assistant"} or getattr(message, "tool_calls", None):
            return None
        safe = self.sentry.verify_output(_message_text(message), context=self.context)
        if safe == _message_text(message):
            return None
        return {"messages": [_replace_content(message, safe)]}


class AsyncPromptSentryMiddleware(AgentMiddleware):  # type: ignore[misc]
    """Async LangChain middleware for ainvoke/astream agent execution."""

    def __init__(self, sentry: AsyncPromptSentryClient, context: SecurityContext | None = None) -> None:
        if ToolMessage is None:
            raise ImportError("Install prompt-sentry[langchain] to use AsyncPromptSentryMiddleware")
        self.sentry = sentry
        self.context = (context or SecurityContext()).with_updates(framework="langchain")

    async def awrap_model_call(self, request: Any, handler: Any) -> Any:
        messages = list(request.messages)
        for index in range(len(messages) - 1, -1, -1):
            message = messages[index]
            if _message_role(message) in {"human", "user"}:
                safe = await self.sentry.protect_text(
                    _message_text(message), source="user_prompt", context=self.context
                )
                messages[index] = _replace_content(message, safe)
                request = request.override(messages=messages)
                break
        return await handler(request)

    async def awrap_tool_call(self, request: Any, handler: Any) -> Any:
        call = request.tool_call
        name = str(call["name"])
        arguments = dict(call.get("args", {}))
        call_id = str(call.get("id", "unknown"))
        context = self.context.with_updates(tool_call_id=call_id)
        review = await self.sentry.review_tool_call(name, arguments, context=context)
        if review.denied:
            return ToolMessage(content=safe_tool_error(review.reason), tool_call_id=call_id, name=name, status="error")
        result = await handler(request)
        return await _aprotect_tool_result(result, self.sentry, context)

    async def aafter_model(self, state: Any, runtime: Any) -> dict[str, Any] | None:
        del runtime
        messages = list(state.get("messages", ()))
        if not messages:
            return None
        message = messages[-1]
        if _message_role(message) not in {"ai", "assistant"} or getattr(message, "tool_calls", None):
            return None
        safe = await self.sentry.verify_output(_message_text(message), context=self.context)
        if safe == _message_text(message):
            return None
        return {"messages": [_replace_content(message, safe)]}


def _message_role(message: Any) -> str:
    if isinstance(message, dict):
        return str(message.get("role", message.get("type", "")))
    return str(getattr(message, "type", getattr(message, "role", "")))


def _message_text(message: Any) -> str:
    content = message.get("content", "") if isinstance(message, dict) else getattr(message, "content", "")
    return content if isinstance(content, str) else str(content)


def _replace_content(message: Any, content: str) -> Any:
    if isinstance(message, dict):
        return {**message, "content": content}
    if hasattr(message, "model_copy"):
        return message.model_copy(update={"content": content})
    message.content = content
    return message


def _protect_tool_result(result: Any, sentry: PromptSentryClient, context: SecurityContext) -> Any:
    if hasattr(result, "content") or isinstance(result, dict) and "content" in result:
        return _replace_content(result, sentry.protect_tool_output(_message_text(result), context=context))
    update = getattr(result, "update", None)
    if isinstance(update, dict) and update.get("messages"):
        messages = update["messages"]
        is_list = isinstance(messages, list)
        items = messages if is_list else [messages]
        protected = [
            _replace_content(item, sentry.protect_tool_output(_message_text(item), context=context)) for item in items
        ]
        return replace(result, update={**update, "messages": protected if is_list else protected[0]})
    return result


async def _aprotect_tool_result(
    result: Any,
    sentry: AsyncPromptSentryClient,
    context: SecurityContext,
) -> Any:
    if hasattr(result, "content") or isinstance(result, dict) and "content" in result:
        protected = await sentry.protect_tool_output(_message_text(result), context=context)
        return _replace_content(result, protected)
    update = getattr(result, "update", None)
    if isinstance(update, dict) and update.get("messages"):
        messages = update["messages"]
        is_list = isinstance(messages, list)
        items = messages if is_list else [messages]
        protected = []
        for item in items:
            content = await sentry.protect_tool_output(_message_text(item), context=context)
            protected.append(_replace_content(item, content))
        return replace(result, update={**update, "messages": protected if is_list else protected[0]})
    return result
