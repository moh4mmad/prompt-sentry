from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

from prompt_sentry.client import AsyncPromptSentryClient, PromptSentryClient
from prompt_sentry.exceptions import safe_tool_error
from prompt_sentry.models import SecurityContext


class AnthropicToolAgent:
    """A protected Anthropic Messages API client-tool loop."""

    def __init__(
        self,
        *,
        anthropic_client: Any,
        sentry: PromptSentryClient,
        model: str,
        tools: list[dict[str, Any]],
        handlers: Mapping[str, Callable[..., Any]],
        context: SecurityContext | None = None,
        system: str | None = None,
        max_tokens: int = 1024,
        max_iterations: int = 8,
    ) -> None:
        self.anthropic = anthropic_client
        self.sentry = sentry
        self.model = model
        self.tools = tools
        self.handlers = dict(handlers)
        self.context = (context or SecurityContext()).with_updates(framework="anthropic", model=model)
        self.system = system
        self.max_tokens = max_tokens
        self.max_iterations = max_iterations

    def run(self, user_input: str) -> str:
        safe_input = self.sentry.protect_text(user_input, source="user_prompt", context=self.context)
        messages: list[dict[str, Any]] = [{"role": "user", "content": safe_input}]

        for _ in range(self.max_iterations):
            response = self.anthropic.messages.create(
                model=self.model,
                max_tokens=self.max_tokens,
                tools=self.tools,
                messages=messages,
                **({"system": self.system} if self.system else {}),
            )
            calls = [block for block in response.content if _attribute(block, "type") == "tool_use"]
            if not calls:
                text = "".join(
                    str(_attribute(block, "text"))
                    for block in response.content
                    if _attribute(block, "type") == "text"
                )
                return self.sentry.verify_output(text, context=self.context)

            messages.append({"role": "assistant", "content": response.content})
            results = []
            for call in calls:
                name = str(_attribute(call, "name"))
                call_id = str(_attribute(call, "id"))
                arguments = dict(_attribute(call, "input") or {})
                context = self.context.with_updates(tool_call_id=call_id)
                output, is_error = self._execute(name, arguments, context)
                results.append(
                    {"type": "tool_result", "tool_use_id": call_id, "content": output, "is_error": is_error}
                )
            messages.append({"role": "user", "content": results})

        raise RuntimeError(f"Anthropic tool loop exceeded {self.max_iterations} iterations")

    def _execute(self, name: str, arguments: dict[str, Any], context: SecurityContext) -> tuple[str, bool]:
        handler = self.handlers.get(name)
        if handler is None:
            return safe_tool_error(f"Unknown tool '{name}'", code="unknown_tool"), True
        review = self.sentry.review_tool_call(name, arguments, context=context)
        if review.denied:
            return safe_tool_error(review.reason), True
        try:
            result = handler(**arguments)
        except Exception:
            return safe_tool_error(f"Tool '{name}' failed", code="tool_error"), True
        protected = self.sentry.protect_tool_output(result, context=context)
        return protected, '"ok":false' in protected.replace(" ", "").lower()


def _attribute(value: Any, name: str) -> Any:
    return value.get(name) if isinstance(value, dict) else getattr(value, name)


class AsyncAnthropicToolAgent:
    """Async protected Anthropic Messages API client-tool loop."""

    def __init__(
        self,
        *,
        anthropic_client: Any,
        sentry: AsyncPromptSentryClient,
        model: str,
        tools: list[dict[str, Any]],
        handlers: Mapping[str, Callable[..., Any]],
        context: SecurityContext | None = None,
        system: str | None = None,
        max_tokens: int = 1024,
        max_iterations: int = 8,
    ) -> None:
        self.anthropic = anthropic_client
        self.sentry = sentry
        self.model = model
        self.tools = tools
        self.handlers = dict(handlers)
        self.context = (context or SecurityContext()).with_updates(framework="anthropic", model=model)
        self.system = system
        self.max_tokens = max_tokens
        self.max_iterations = max_iterations

    async def run(self, user_input: str) -> str:
        import inspect

        safe_input = await self.sentry.protect_text(user_input, source="user_prompt", context=self.context)
        messages: list[dict[str, Any]] = [{"role": "user", "content": safe_input}]
        for _ in range(self.max_iterations):
            response = await self.anthropic.messages.create(
                model=self.model,
                max_tokens=self.max_tokens,
                tools=self.tools,
                messages=messages,
                **({"system": self.system} if self.system else {}),
            )
            calls = [block for block in response.content if _attribute(block, "type") == "tool_use"]
            if not calls:
                text = "".join(
                    str(_attribute(block, "text"))
                    for block in response.content
                    if _attribute(block, "type") == "text"
                )
                return await self.sentry.verify_output(text, context=self.context)
            messages.append({"role": "assistant", "content": response.content})
            results = []
            for call in calls:
                name = str(_attribute(call, "name"))
                call_id = str(_attribute(call, "id"))
                arguments = dict(_attribute(call, "input") or {})
                context = self.context.with_updates(tool_call_id=call_id)
                handler = self.handlers.get(name)
                review = await self.sentry.review_tool_call(name, arguments, context=context)
                is_error = handler is None or review.denied
                if handler is None:
                    output = safe_tool_error(f"Unknown tool '{name}'", code="unknown_tool")
                elif review.denied:
                    output = safe_tool_error(review.reason)
                else:
                    try:
                        value = handler(**arguments)
                        if inspect.isawaitable(value):
                            value = await value
                        output = await self.sentry.protect_tool_output(value, context=context)
                        is_error = '"ok":false' in output.replace(" ", "").lower()
                    except Exception:
                        output = safe_tool_error(f"Tool '{name}' failed", code="tool_error")
                        is_error = True
                results.append(
                    {"type": "tool_result", "tool_use_id": call_id, "content": output, "is_error": is_error}
                )
            messages.append({"role": "user", "content": results})
        raise RuntimeError(f"Anthropic tool loop exceeded {self.max_iterations} iterations")
