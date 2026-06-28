from __future__ import annotations

import inspect
from collections.abc import Callable
from functools import wraps
from typing import Any

from prompt_sentry.client import AsyncPromptSentryClient, PromptSentryClient
from prompt_sentry.exceptions import PromptSentryBlocked, safe_tool_error
from prompt_sentry.models import SecurityContext


def promptsentry_tool(
    sentry: PromptSentryClient | AsyncPromptSentryClient,
    *,
    context: SecurityContext | None = None,
    name: str | None = None,
) -> Callable[[Callable[..., Any]], Callable[..., str]]:
    """Protect a function before decorating it with CrewAI's @tool."""

    base_context = (context or SecurityContext()).with_updates(framework="crewai")

    def decorator(function: Callable[..., Any]) -> Callable[..., str]:
        tool_name = name or function.__name__

        if inspect.iscoroutinefunction(function):

            @wraps(function)
            async def async_protected(**kwargs: Any) -> str:
                if not isinstance(sentry, AsyncPromptSentryClient):
                    raise TypeError("Async CrewAI tools require AsyncPromptSentryClient")
                review = await sentry.review_tool_call(tool_name, kwargs, context=base_context)
                if review.denied:
                    return safe_tool_error(review.reason)
                return await sentry.protect_tool_output(await function(**kwargs), context=base_context)

            return async_protected  # type: ignore[return-value]

        @wraps(function)
        def protected(**kwargs: Any) -> str:
            if isinstance(sentry, AsyncPromptSentryClient):
                raise TypeError("Sync CrewAI tools require PromptSentryClient")
            review = sentry.review_tool_call(tool_name, kwargs, context=base_context)
            if review.denied:
                return safe_tool_error(review.reason)
            return sentry.protect_tool_output(function(**kwargs), context=base_context)

        return protected

    return decorator


class PromptSentryCrew:
    """Composition wrapper protecting CrewAI kickoff inputs and final output."""

    def __init__(self, crew: Any, sentry: PromptSentryClient, context: SecurityContext | None = None) -> None:
        self.crew = crew
        self.sentry = sentry
        self.context = (context or SecurityContext()).with_updates(framework="crewai")

    def kickoff(self, inputs: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        safe_inputs = {
            key: self.sentry.protect_text(value, source="user_prompt", context=self.context)
            if isinstance(value, str)
            else value
            for key, value in (inputs or {}).items()
        }
        result = self.crew.kickoff(inputs=safe_inputs, **kwargs)
        raw = getattr(result, "raw", str(result))
        safe = self.sentry.verify_output(str(raw), context=self.context)
        if hasattr(result, "raw"):
            result.raw = safe
            return result
        return safe


def prompt_sentry_guardrail(
    sentry: PromptSentryClient,
    context: SecurityContext | None = None,
) -> Callable[[Any], tuple[bool, Any]]:
    guard_context = (context or SecurityContext()).with_updates(framework="crewai")

    def guardrail(output: Any) -> tuple[bool, Any]:
        raw = getattr(output, "raw", str(output))
        try:
            return True, sentry.verify_output(str(raw), context=guard_context)
        except PromptSentryBlocked as exc:
            return False, str(exc)

    return guardrail
