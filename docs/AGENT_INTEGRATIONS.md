# Agent integrations

PromptSentry's Python SDK protects the four trust boundaries shared by agent frameworks: user input, retrieved or tool-provided content, proposed tool calls, and final model output.

## Install

Install only the framework adapter you use:

```bash
pip install -e ".[langchain]"
pip install -e ".[llamaindex]"
pip install -e ".[openai-agent]"
pip install -e ".[anthropic-agent]"
pip install -e ".[crewai]"
pip install -e ".[mcp]"
# Or all adapters:
pip install -e ".[agents]"
```

The SDK reads `PROMPT_SENTRY_URL` (default `http://localhost:8100`) and `PROMPT_SENTRY_API_KEY`. Framework dependencies remain optional and are not installed with the firewall service.

## Shared client

```python
from prompt_sentry import PromptSentryClient, SecurityContext

client = PromptSentryClient(timeout=5.0, max_retries=1, fail_open=False)
context = SecurityContext(
    tenant_id="acme",
    user_id="user-42",
    session_id="session-7",
    agent_run_id="run-9",
    allowed_tools=("search",),
)

safe_input = client.protect_text(user_input, source="user_prompt", context=context)
```

`fail_open=False` is the production default. Setting it to `True` allows execution after network failures or server errors and is intended only for development; authentication and invalid-response errors always fail closed. Sync and async clients expose the same inspection and tool-review contract.

## Framework entry points

| Framework | Integration |
|---|---|
| LangChain | `PromptSentryMiddleware` or `AsyncPromptSentryMiddleware` |
| LlamaIndex | ingestion transform, node postprocessor, sync/async query-engine wrappers |
| OpenAI | `OpenAIToolAgent` or `AsyncOpenAIToolAgent` using the Responses API |
| Anthropic | `AnthropicToolAgent` or `AsyncAnthropicToolAgent` using Messages tool-use blocks |
| CrewAI | `@promptsentry_tool`, `PromptSentryCrew`, and task guardrail factory |
| MCP | `ProtectedFastMCP`, stdio/HTTP upstream clients, and `PromptSentryMCPGateway` |

Complete runnable programs are under `examples/integrations/`. Provider examples require an explicit model environment variable so the repository never silently changes models.

## Tool denial behavior

A denied tool is never invoked. The adapter returns a framework-native error payload to the model so it can recover or choose an allowed tool. Unknown tools are also denied locally. Plain-text tool output may be sanitized; structured output is returned unchanged only for allow/monitor decisions and otherwise becomes a safe error payload.

## MCP boundary

Owned FastMCP servers can register protected functions through `ProtectedFastMCP`. The gateway can proxy arbitrary upstream servers over stdio or Streamable HTTP, filter `tools/list`, review `tools/call`, and inspect results. Configure upstream HTTP headers as service credentials; never copy a caller's bearer token into the upstream configuration.

MCP is pinned to the stable 1.x API. The lower bound is 1.26 because current CrewAI requires that compatible release; v2 prereleases are excluded.

Anthropic server-executed tools run on Anthropic infrastructure before application code receives the response. The Anthropic adapter protects client-executed tools and final returned content, but cannot pre-authorize those server-side executions.

Framework references: [LangChain middleware](https://docs.langchain.com/oss/python/langchain/middleware/overview), [LlamaIndex query engines](https://developers.llamaindex.ai/python/framework/module_guides/deploying/query_engine/), [OpenAI function calling](https://developers.openai.com/api/docs/guides/function-calling), [Anthropic tool use](https://platform.claude.com/docs/en/agents-and-tools/tool-use/how-tool-use-works), and [MCP security practices](https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices).

## Tests

The default suite uses mocked providers and records handler invocation counts, so it proves denied tools did not execute without spending API credits. MCP stdio and Streamable HTTP transports run local end-to-end tests. Paid provider smoke tests are opt-in:

```bash
PROMPT_SENTRY_LIVE_TESTS=1 \
OPENAI_API_KEY=... OPENAI_MODEL=... \
ANTHROPIC_API_KEY=... ANTHROPIC_MODEL=... \
python -m pytest -m live_integration tests/integration/test_live_agents.py
```
