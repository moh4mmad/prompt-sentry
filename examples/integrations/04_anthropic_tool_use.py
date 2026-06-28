"""Run with ANTHROPIC_API_KEY and ANTHROPIC_MODEL after installing .[anthropic-agent]."""

import os

from anthropic import Anthropic

from prompt_sentry import PromptSentryClient, SecurityContext
from prompt_sentry.integrations.anthropic import AnthropicToolAgent


def weather(city: str) -> dict[str, str]:
    return {"city": city, "forecast": "sunny"}


def main() -> None:
    model = os.environ["ANTHROPIC_MODEL"]
    tool = {
        "name": "weather",
        "description": "Get a weather forecast",
        "input_schema": {
            "type": "object",
            "properties": {"city": {"type": "string"}},
            "required": ["city"],
        },
        "strict": True,
    }
    context = SecurityContext(agent_run_id="anthropic-demo", allowed_tools=("weather",))
    agent = AnthropicToolAgent(
        anthropic_client=Anthropic(),
        sentry=PromptSentryClient(),
        model=model,
        tools=[tool],
        handlers={"weather": weather},
        context=context,
    )
    print(agent.run("What is the weather in Tokyo?"))


if __name__ == "__main__":
    main()
