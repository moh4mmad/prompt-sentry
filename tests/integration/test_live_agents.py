import os

import pytest

from prompt_sentry import PromptSentryClient, SecurityContext

LIVE = os.getenv("PROMPT_SENTRY_LIVE_TESTS") == "1"


@pytest.mark.live_integration
@pytest.mark.skipif(
    not LIVE or not os.getenv("OPENAI_API_KEY") or not os.getenv("OPENAI_MODEL"),
    reason="live OpenAI disabled",
)
def test_live_openai_response():
    from openai import OpenAI

    from prompt_sentry.integrations.openai import OpenAIToolAgent

    agent = OpenAIToolAgent(
        openai_client=OpenAI(),
        sentry=PromptSentryClient(),
        model=os.environ["OPENAI_MODEL"],
        tools=[],
        handlers={},
        context=SecurityContext(agent_run_id="live-openai"),
    )
    assert agent.run("Reply with exactly: safe")


@pytest.mark.live_integration
@pytest.mark.skipif(
    not LIVE or not os.getenv("ANTHROPIC_API_KEY") or not os.getenv("ANTHROPIC_MODEL"),
    reason="live Anthropic disabled",
)
def test_live_anthropic_response():
    from anthropic import Anthropic

    from prompt_sentry.integrations.anthropic import AnthropicToolAgent

    agent = AnthropicToolAgent(
        anthropic_client=Anthropic(),
        sentry=PromptSentryClient(),
        model=os.environ["ANTHROPIC_MODEL"],
        tools=[],
        handlers={},
        context=SecurityContext(agent_run_id="live-anthropic"),
    )
    assert agent.run("Reply with exactly: safe")
