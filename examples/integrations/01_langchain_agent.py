"""Run with: pip install -e '.[langchain]' and set LANGCHAIN_MODEL/provider credentials."""

import os

from langchain.agents import create_agent
from langchain.tools import tool

from prompt_sentry import PromptSentryClient, SecurityContext
from prompt_sentry.integrations.langchain import PromptSentryMiddleware


@tool
def search(query: str) -> str:
    """Search a small demonstration knowledge base."""
    return f"Safe result for {query}"


def main() -> None:
    model = os.environ["LANGCHAIN_MODEL"]
    sentry = PromptSentryClient()
    context = SecurityContext(agent_run_id="langchain-demo", allowed_tools=("search",))
    agent = create_agent(
        model=model,
        tools=[search],
        middleware=[PromptSentryMiddleware(sentry, context)],
    )
    result = agent.invoke({"messages": [{"role": "user", "content": "Search for PromptSentry"}]})
    print(result["messages"][-1].content)


if __name__ == "__main__":
    main()
