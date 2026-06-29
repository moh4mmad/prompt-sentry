import os

import pytest

from prompt_sentry import PromptSentryClient, SecurityContext
from prompt_sentry.benchmark.live import LiveAgent
from prompt_sentry.benchmark.loader import load_cases
from prompt_sentry.benchmark.models import BenchmarkVariant

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


@pytest.mark.live_integration
@pytest.mark.skipif(
    not LIVE or not os.getenv("OPENAI_API_KEY") or not os.getenv("OPENAI_MODEL"),
    reason="live OpenAI benchmark disabled",
)
def test_live_openai_benchmark_workflow():
    from app.core.config import Settings
    from app.middleware.firewall import PromptSentry

    trace = LiveAgent(
        PromptSentry(Settings()),
        provider="openai",
        model=os.environ["OPENAI_MODEL"],
    ).run(load_cases()[0], BenchmarkVariant.BENIGN, protected=True)
    assert trace.error is None
    assert trace.final_output


@pytest.mark.live_integration
@pytest.mark.skipif(
    not LIVE or not os.getenv("ANTHROPIC_API_KEY") or not os.getenv("ANTHROPIC_MODEL"),
    reason="live Anthropic benchmark disabled",
)
def test_live_anthropic_benchmark_workflow():
    from app.core.config import Settings
    from app.middleware.firewall import PromptSentry

    trace = LiveAgent(
        PromptSentry(Settings()),
        provider="anthropic",
        model=os.environ["ANTHROPIC_MODEL"],
    ).run(load_cases()[0], BenchmarkVariant.BENIGN, protected=True)
    assert trace.error is None
    assert trace.final_output
