import asyncio
from types import SimpleNamespace

import pytest

from prompt_sentry.exceptions import PromptSentryBlocked
from prompt_sentry.integrations.crewai import PromptSentryCrew, promptsentry_tool
from prompt_sentry.integrations.llamaindex import PromptSentryIngestionTransform
from prompt_sentry.integrations.mcp import PromptSentryMCPGateway, ProtectedFastMCP
from prompt_sentry.models import Action, SecurityContext, ToolReviewResult


class FrameworkSentry:
    def __init__(self, *, blocked_text=(), blocked_tools=()):
        self.blocked_text = tuple(blocked_text)
        self.blocked_tools = set(blocked_tools)

    def protect_text(self, text, **kwargs):
        if any(value in text for value in self.blocked_text):
            raise PromptSentryBlocked(action="block", risk_score=0.9, attack_types=("indirect_injection",))
        return text.replace("sanitize-me", "clean")

    def verify_output(self, text, **kwargs):
        return text

    def review_tool_call(self, name, arguments, **kwargs):
        denied = name in self.blocked_tools
        return ToolReviewResult(
            "tool",
            Action.BLOCK if denied else Action.ALLOW,
            0.9 if denied else 0.05,
            "high" if denied else "low",
            "blocked" if denied else "allowed",
        )

    def protect_tool_output(self, value, **kwargs):
        return str(value)


class FakeNode:
    def __init__(self, node_id, text):
        self.node_id = node_id
        self.text = text
        self.metadata = {}

    def get_content(self):
        return self.text

    def set_content(self, value):
        self.text = value


def test_llamaindex_ingestion_drops_blocked_nodes_and_clones_sanitized_nodes():
    pytest.importorskip("llama_index.core")
    original = FakeNode("safe", "sanitize-me")
    transform = PromptSentryIngestionTransform(FrameworkSentry(blocked_text=("hidden attack",)))
    result = transform([original, FakeNode("bad", "hidden attack")])

    assert len(result) == 1
    assert result[0].text == "clean"
    assert original.text == "sanitize-me"


def test_crewai_protected_tool_never_executes_when_denied():
    executed = []
    protected = promptsentry_tool(FrameworkSentry(blocked_tools={"delete"}), name="delete")(
        lambda **kwargs: executed.append(kwargs) or "deleted"
    )

    result = protected(target="all")
    assert executed == []
    assert "promptsentry_denied" in result


def test_crewai_wrapper_inspects_kickoff_and_output():
    crew = SimpleNamespace(kickoff=lambda **kwargs: f"result:{kwargs['inputs']['question']}")
    protected = PromptSentryCrew(crew, FrameworkSentry())
    assert protected.kickoff(inputs={"question": "hello"}) == "result:hello"


def test_crewai_multi_agent_tools_keep_separate_security_contexts():
    class RecordingSentry(FrameworkSentry):
        def __init__(self):
            super().__init__(blocked_tools={"writer_delete"})
            self.contexts = []

        def review_tool_call(self, name, arguments, **kwargs):
            self.contexts.append(kwargs["context"].metadata["agent_name"])
            return super().review_tool_call(name, arguments, **kwargs)

    sentry = RecordingSentry()
    researcher = promptsentry_tool(
        sentry,
        name="research",
        context=SecurityContext(metadata={"agent_name": "researcher"}),
    )(lambda **kwargs: "research complete")
    writer = promptsentry_tool(
        sentry,
        name="writer_delete",
        context=SecurityContext(metadata={"agent_name": "writer"}),
    )(lambda **kwargs: pytest.fail("writer's denied tool executed"))

    assert researcher(topic="security") == "research complete"
    assert "promptsentry_denied" in writer(target="drafts")
    assert sentry.contexts == ["researcher", "writer"]


class FakeFastMCP:
    def __init__(self):
        self.registered = {}

    def tool(self, *args, **kwargs):
        del args

        def decorator(function):
            self.registered[kwargs.get("name", function.__name__)] = function
            return function

        return decorator


def test_owned_mcp_tool_is_blocked_before_execution():
    executed = []
    server = FakeFastMCP()
    protected = ProtectedFastMCP(server, FrameworkSentry(blocked_tools={"danger"}))

    @protected.tool(name="danger")
    def danger(value: str):
        executed.append(value)
        return value

    result = server.registered["danger"](value="payload")
    assert executed == []
    assert "promptsentry_denied" in result


class AsyncFrameworkSentry:
    def __init__(self, blocked=()):
        self.blocked = set(blocked)

    async def review_tool_call(self, name, arguments, **kwargs):
        denied = name in self.blocked
        return ToolReviewResult("tool", Action.BLOCK if denied else Action.ALLOW, 0.9, "high", "blocked")

    async def protect_tool_output(self, value, **kwargs):
        return str(value)


class FakeUpstream:
    def __init__(self):
        self.calls = []

    async def list_tools(self):
        return [SimpleNamespace(name="safe"), SimpleNamespace(name="danger")]

    async def call_tool(self, name, arguments):
        self.calls.append((name, arguments))
        return SimpleNamespace(content=[SimpleNamespace(type="text", text="result")])


def test_mcp_gateway_filters_and_blocks_without_forwarding():
    async def run():
        upstream = FakeUpstream()
        gateway = PromptSentryMCPGateway(
            upstream,
            AsyncFrameworkSentry(blocked={"danger"}),
            SecurityContext(allowed_tools=("safe", "danger")),
        )
        assert [tool.name for tool in await gateway.list_tools()] == ["safe", "danger"]
        denied = await gateway.call_tool("danger", {})
        assert upstream.calls == []
        is_error = denied.get("isError") if isinstance(denied, dict) else denied.isError
        assert is_error is True
        await gateway.call_tool("safe", {"query": "ok"})
        assert upstream.calls == [("safe", {"query": "ok"})]

    asyncio.run(run())
