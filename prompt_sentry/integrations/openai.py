from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from typing import Any

from prompt_sentry.client import AsyncPromptSentryClient, PromptSentryClient
from prompt_sentry.exceptions import safe_tool_error
from prompt_sentry.models import SecurityContext


class OpenAIToolAgent:
    """A protected OpenAI Responses API function-calling loop."""

    def __init__(
        self,
        *,
        openai_client: Any,
        sentry: PromptSentryClient,
        model: str,
        tools: list[dict[str, Any]],
        handlers: Mapping[str, Callable[..., Any]],
        context: SecurityContext | None = None,
        instructions: str | None = None,
        max_iterations: int = 8,
    ) -> None:
        self.openai = openai_client
        self.sentry = sentry
        self.model = model
        self.tools = tools
        self.handlers = dict(handlers)
        self.context = (context or SecurityContext()).with_updates(framework="openai", model=model)
        self.instructions = instructions
        self.max_iterations = max_iterations

    def run(self, user_input: str) -> str:
        safe_input = self.sentry.protect_text(user_input, source="user_prompt", context=self.context)
        response = self.openai.responses.create(
            model=self.model,
            input=safe_input,
            tools=self.tools,
            **({"instructions": self.instructions} if self.instructions else {}),
        )

        for _ in range(self.max_iterations):
            calls = [item for item in response.output if _attribute(item, "type") == "function_call"]
            if not calls:
                return self.sentry.verify_output(str(response.output_text), context=self.context)

            outputs = []
            for call in calls:
                name = str(_attribute(call, "name"))
                call_id = str(_attribute(call, "call_id"))
                call_context = self.context.with_updates(tool_call_id=call_id)
                arguments = _arguments(_attribute(call, "arguments"))
                output = self._execute(name, arguments, call_context)
                outputs.append({"type": "function_call_output", "call_id": call_id, "output": output})

            response = self.openai.responses.create(
                model=self.model,
                previous_response_id=response.id,
                input=outputs,
                tools=self.tools,
                **({"instructions": self.instructions} if self.instructions else {}),
            )

        raise RuntimeError(f"OpenAI tool loop exceeded {self.max_iterations} iterations")

    def _execute(self, name: str, arguments: dict[str, Any], context: SecurityContext) -> str:
        handler = self.handlers.get(name)
        if handler is None:
            return safe_tool_error(f"Unknown tool '{name}'", code="unknown_tool")
        review = self.sentry.review_tool_call(name, arguments, context=context)
        if review.denied:
            return safe_tool_error(review.reason)
        try:
            result = handler(**arguments)
        except Exception:
            return safe_tool_error(f"Tool '{name}' failed", code="tool_error")
        return self.sentry.protect_tool_output(result, context=context)


class AsyncOpenAIToolAgent:
    """Async protected OpenAI Responses API function-calling loop."""

    def __init__(
        self,
        *,
        openai_client: Any,
        sentry: AsyncPromptSentryClient,
        model: str,
        tools: list[dict[str, Any]],
        handlers: Mapping[str, Callable[..., Any]],
        context: SecurityContext | None = None,
        instructions: str | None = None,
        max_iterations: int = 8,
    ) -> None:
        self.openai = openai_client
        self.sentry = sentry
        self.model = model
        self.tools = tools
        self.handlers = dict(handlers)
        self.context = (context or SecurityContext()).with_updates(framework="openai", model=model)
        self.instructions = instructions
        self.max_iterations = max_iterations

    async def run(self, user_input: str) -> str:
        safe_input = await self.sentry.protect_text(user_input, source="user_prompt", context=self.context)
        response = await self.openai.responses.create(
            model=self.model,
            input=safe_input,
            tools=self.tools,
            **({"instructions": self.instructions} if self.instructions else {}),
        )
        for _ in range(self.max_iterations):
            calls = [item for item in response.output if _attribute(item, "type") == "function_call"]
            if not calls:
                return await self.sentry.verify_output(str(response.output_text), context=self.context)
            outputs = []
            for call in calls:
                name = str(_attribute(call, "name"))
                call_id = str(_attribute(call, "call_id"))
                context = self.context.with_updates(tool_call_id=call_id)
                output = await self._execute(name, _arguments(_attribute(call, "arguments")), context)
                outputs.append({"type": "function_call_output", "call_id": call_id, "output": output})
            response = await self.openai.responses.create(
                model=self.model,
                previous_response_id=response.id,
                input=outputs,
                tools=self.tools,
                **({"instructions": self.instructions} if self.instructions else {}),
            )
        raise RuntimeError(f"OpenAI tool loop exceeded {self.max_iterations} iterations")

    async def _execute(self, name: str, arguments: dict[str, Any], context: SecurityContext) -> str:
        import inspect

        handler = self.handlers.get(name)
        if handler is None:
            return safe_tool_error(f"Unknown tool '{name}'", code="unknown_tool")
        review = await self.sentry.review_tool_call(name, arguments, context=context)
        if review.denied:
            return safe_tool_error(review.reason)
        try:
            result = handler(**arguments)
            if inspect.isawaitable(result):
                result = await result
        except Exception:
            return safe_tool_error(f"Tool '{name}' failed", code="tool_error")
        return await self.sentry.protect_tool_output(result, context=context)


def _attribute(value: Any, name: str) -> Any:
    return value.get(name) if isinstance(value, dict) else getattr(value, name)


def _arguments(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    parsed = json.loads(value or "{}")
    if not isinstance(parsed, dict):
        raise ValueError("Function arguments must decode to an object")
    return parsed
