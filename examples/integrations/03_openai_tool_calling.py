"""Run with OPENAI_API_KEY and OPENAI_MODEL after installing .[openai-agent]."""

import os

from openai import OpenAI

from prompt_sentry import PromptSentryClient, SecurityContext
from prompt_sentry.integrations.openai import OpenAIToolAgent


def weather(city: str) -> dict[str, str]:
    return {"city": city, "forecast": "sunny"}


def main() -> None:
    model = os.environ["OPENAI_MODEL"]
    tool = {
        "type": "function",
        "name": "weather",
        "description": "Get a weather forecast",
        "strict": True,
        "parameters": {
            "type": "object",
            "properties": {"city": {"type": "string"}},
            "required": ["city"],
            "additionalProperties": False,
        },
    }
    context = SecurityContext(agent_run_id="openai-demo", allowed_tools=("weather",))
    agent = OpenAIToolAgent(
        openai_client=OpenAI(),
        sentry=PromptSentryClient(),
        model=model,
        tools=[tool],
        handlers={"weather": weather},
        context=context,
    )
    print(agent.run("What is the weather in Tokyo?"))


if __name__ == "__main__":
    main()
