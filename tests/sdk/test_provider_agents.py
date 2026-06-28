import asyncio
from types import SimpleNamespace

import pytest

from prompt_sentry.exceptions import PromptSentryBlocked
from prompt_sentry.integrations.anthropic import AnthropicToolAgent
from prompt_sentry.integrations.openai import AsyncOpenAIToolAgent, OpenAIToolAgent
from prompt_sentry.models import Action, ToolReviewResult


class FakeSentry:
    def __init__(self, blocked_tools=()):
        self.blocked_tools = set(blocked_tools)
        self.calls = []

    def protect_text(self, text, **kwargs):
        self.calls.append(("input", text, kwargs))
        return text

    def verify_output(self, text, **kwargs):
        self.calls.append(("output", text, kwargs))
        return text

    def review_tool_call(self, name, arguments, **kwargs):
        self.calls.append(("review", name, arguments, kwargs))
        denied = name in self.blocked_tools
        return ToolReviewResult(
            "tool",
            Action.BLOCK if denied else Action.ALLOW,
            0.9 if denied else 0.05,
            "high" if denied else "low",
            "denied by test policy" if denied else "allowed",
        )

    def protect_tool_output(self, value, **kwargs):
        self.calls.append(("tool_output", value, kwargs))
        return str(value)


class FakeResponses:
    def __init__(self, responses):
        self.queue = list(responses)
        self.requests = []

    def create(self, **kwargs):
        self.requests.append(kwargs)
        return self.queue.pop(0)


def test_openai_parallel_calls_review_before_execution():
    executed = []
    first = SimpleNamespace(
        id="resp-1",
        output=[
            SimpleNamespace(type="function_call", name="safe", call_id="call-1", arguments='{"value": 1}'),
            SimpleNamespace(type="function_call", name="danger", call_id="call-2", arguments="{}"),
        ],
        output_text="",
    )
    final = SimpleNamespace(id="resp-2", output=[], output_text="finished")
    provider = SimpleNamespace(responses=FakeResponses([first, final]))
    sentry = FakeSentry(blocked_tools={"danger"})

    agent = OpenAIToolAgent(
        openai_client=provider,
        sentry=sentry,
        model="test-model",
        tools=[],
        handlers={
            "safe": lambda value: executed.append(("safe", value)) or "ok",
            "danger": lambda: executed.append(("danger", None)) or "bad",
        },
    )

    assert agent.run("hello") == "finished"
    assert executed == [("safe", 1)]
    outputs = provider.responses.requests[1]["input"]
    assert len(outputs) == 2
    assert "promptsentry_denied" in outputs[1]["output"]


class FakeMessages:
    def __init__(self, responses):
        self.queue = list(responses)
        self.requests = []

    def create(self, **kwargs):
        self.requests.append(kwargs)
        return self.queue.pop(0)


def test_anthropic_denied_tool_is_never_invoked():
    executed = []
    first = SimpleNamespace(
        stop_reason="tool_use",
        content=[SimpleNamespace(type="tool_use", name="delete_all", id="tool-1", input={})],
    )
    final = SimpleNamespace(stop_reason="end_turn", content=[SimpleNamespace(type="text", text="recovered")])
    provider = SimpleNamespace(messages=FakeMessages([first, final]))
    sentry = FakeSentry(blocked_tools={"delete_all"})
    agent = AnthropicToolAgent(
        anthropic_client=provider,
        sentry=sentry,
        model="test-model",
        tools=[],
        handlers={"delete_all": lambda: executed.append(True)},
    )

    assert agent.run("hello") == "recovered"
    assert executed == []
    result = provider.messages.requests[1]["messages"][-1]["content"][0]
    assert result["is_error"] is True
    assert "promptsentry_denied" in result["content"]


def test_async_openai_denied_tool_is_never_invoked():
    class AsyncSentry(FakeSentry):
        async def protect_text(self, text, **kwargs):
            return text

        async def verify_output(self, text, **kwargs):
            return text

        async def review_tool_call(self, name, arguments, **kwargs):
            return super().review_tool_call(name, arguments, **kwargs)

        async def protect_tool_output(self, value, **kwargs):
            return str(value)

    class AsyncResponses(FakeResponses):
        async def create(self, **kwargs):
            return super().create(**kwargs)

    async def run():
        executed = []
        first = SimpleNamespace(
            id="resp-1",
            output=[SimpleNamespace(type="function_call", name="danger", call_id="call-1", arguments="{}")],
            output_text="",
        )
        final = SimpleNamespace(id="resp-2", output=[], output_text="safe")
        provider = SimpleNamespace(responses=AsyncResponses([first, final]))
        agent = AsyncOpenAIToolAgent(
            openai_client=provider,
            sentry=AsyncSentry(blocked_tools={"danger"}),
            model="test-model",
            tools=[],
            handlers={"danger": lambda: executed.append(True)},
        )
        assert await agent.run("hello") == "safe"
        assert executed == []

    asyncio.run(run())


def test_openai_unknown_tool_returns_error_without_execution():
    first = SimpleNamespace(
        id="resp-1",
        output=[SimpleNamespace(type="function_call", name="unknown", call_id="call-1", arguments="{}")],
        output_text="",
    )
    final = SimpleNamespace(id="resp-2", output=[], output_text="recovered")
    provider = SimpleNamespace(responses=FakeResponses([first, final]))
    agent = OpenAIToolAgent(
        openai_client=provider,
        sentry=FakeSentry(),
        model="test-model",
        tools=[],
        handlers={},
    )
    assert agent.run("hello") == "recovered"
    assert "unknown_tool" in provider.responses.requests[1]["input"][0]["output"]


def test_provider_final_secret_leak_aborts_response():
    class OutputBlockingSentry(FakeSentry):
        def verify_output(self, text, **kwargs):
            raise PromptSentryBlocked(
                action="alert",
                risk_score=0.99,
                attack_types=("sensitive_output_leak",),
            )

    final = SimpleNamespace(id="resp", output=[], output_text="sk-test-secret-value")
    provider = SimpleNamespace(responses=FakeResponses([final]))
    agent = OpenAIToolAgent(
        openai_client=provider,
        sentry=OutputBlockingSentry(),
        model="test-model",
        tools=[],
        handlers={},
    )
    with pytest.raises(PromptSentryBlocked):
        agent.run("hello")
