"""Run with CREWAI_MODEL/provider credentials after installing .[crewai]."""

import os

from crewai import Agent, Crew, Task
from crewai.tools import tool

from prompt_sentry import PromptSentryClient, SecurityContext
from prompt_sentry.integrations.crewai import PromptSentryCrew, promptsentry_tool

sentry = PromptSentryClient()
context = SecurityContext(agent_run_id="crewai-demo", allowed_tools=("lookup",))


@tool("lookup")
@promptsentry_tool(sentry, context=context, name="lookup")
def lookup(query: str) -> str:
    """Look up safe demonstration content."""
    return f"Information about {query}"


def main() -> None:
    researcher = Agent(
        role="Researcher",
        goal="Answer the user's question",
        backstory="A careful research agent",
        tools=[lookup],
        llm=os.environ["CREWAI_MODEL"],
    )
    task = Task(description="Research {question}", expected_output="A concise answer", agent=researcher)
    protected = PromptSentryCrew(Crew(agents=[researcher], tasks=[task]), sentry, context)
    print(protected.kickoff(inputs={"question": "PromptSentry"}))


if __name__ == "__main__":
    main()
