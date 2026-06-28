import asyncio

import pytest

from prompt_sentry.integrations.langchain import PromptSentryMiddleware
from prompt_sentry.integrations.llamaindex import PromptSentryNodePostprocessor
from prompt_sentry.integrations.mcp import ProtectedFastMCP
from tests.sdk.test_framework_adapters import FrameworkSentry


def test_langchain_real_message_and_request_types():
    pytest.importorskip("langchain")
    from langchain.agents.middleware import ModelRequest, ToolCallRequest
    from langchain.messages import HumanMessage, ToolMessage

    sentry = FrameworkSentry(blocked_tools={"danger"})
    middleware = PromptSentryMiddleware(sentry)
    message = HumanMessage(content="sanitize-me")
    request = ModelRequest(model=None, messages=[message], state={"messages": [message]})
    protected_request = middleware.wrap_model_call(request, lambda value: value)
    assert protected_request.messages[-1].content == "clean"

    tool_request = ToolCallRequest(
        tool_call={"name": "danger", "args": {}, "id": "call-1", "type": "tool_call"},
        tool=None,
        state={},
        runtime=None,
    )
    result = middleware.wrap_tool_call(tool_request, lambda _: pytest.fail("denied tool executed"))
    assert isinstance(result, ToolMessage)
    assert result.status == "error"


def test_langchain_command_tool_output_is_inspected():
    pytest.importorskip("langchain")
    from langchain.agents.middleware import ToolCallRequest
    from langchain.messages import ToolMessage
    from langgraph.types import Command

    middleware = PromptSentryMiddleware(FrameworkSentry())
    request = ToolCallRequest(
        tool_call={"name": "safe", "args": {}, "id": "call-1", "type": "tool_call"},
        tool=None,
        state={},
        runtime=None,
    )
    command = Command(update={"messages": [ToolMessage(content="result", tool_call_id="call-1")]})
    result = middleware.wrap_tool_call(request, lambda _: command)
    assert result.update["messages"][0].content == "result"


def test_llamaindex_real_node_postprocessor_types():
    pytest.importorskip("llama_index.core")
    from llama_index.core.schema import NodeWithScore, QueryBundle, TextNode

    postprocessor = PromptSentryNodePostprocessor(FrameworkSentry(blocked_text=("hidden attack",)))
    nodes = [
        NodeWithScore(node=TextNode(text="safe")),
        NodeWithScore(node=TextNode(text="hidden attack")),
    ]
    result = postprocessor.postprocess_nodes(nodes, query_bundle=QueryBundle("question"))
    assert len(result) == 1
    assert result[0].text == "safe"


def test_llamaindex_ingestion_pipeline_accepts_transform():
    pytest.importorskip("llama_index.core")
    from llama_index.core.ingestion import IngestionPipeline

    from prompt_sentry.integrations.llamaindex import PromptSentryIngestionTransform

    transform = PromptSentryIngestionTransform(FrameworkSentry())
    pipeline = IngestionPipeline(transformations=[transform])
    assert pipeline.transformations == [transform]


def test_fastmcp_real_registration_blocks_execution():
    pytest.importorskip("mcp")
    from mcp.server.fastmcp import FastMCP

    async def run():
        executed = []
        raw = FastMCP("test")
        server = ProtectedFastMCP(raw, FrameworkSentry(blocked_tools={"danger"}))

        @server.tool()
        def danger(value: str) -> str:
            executed.append(value)
            return value

        result = await raw.call_tool("danger", {"value": "payload"})
        assert executed == []
        content, structured = result
        assert "promptsentry_denied" in content[0].text
        assert "promptsentry_denied" in structured["result"]

    asyncio.run(run())


def test_crewai_real_tool_wrapper_blocks_execution():
    pytest.importorskip("crewai")
    from crewai.tools import tool

    from prompt_sentry.integrations.crewai import promptsentry_tool

    executed = []

    @tool("danger")
    @promptsentry_tool(FrameworkSentry(blocked_tools={"danger"}), name="danger")
    def danger(value: str) -> str:
        """A dangerous tool used to verify enforcement order."""
        executed.append(value)
        return value

    result = danger.run(value="payload")
    assert executed == []
    assert "promptsentry_denied" in result
