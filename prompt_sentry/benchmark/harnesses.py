from __future__ import annotations

from dataclasses import dataclass

from prompt_sentry.benchmark.models import BenchmarkCase, BenchmarkScenario, BenchmarkVariant


@dataclass(frozen=True)
class ScenarioHarness:
    scenario: BenchmarkScenario
    boundary: str
    workflow: str
    inspect_attack_before_tool_use: bool = True

    def prompt(self, case: BenchmarkCase, variant: BenchmarkVariant) -> str:
        hostile = (
            f"\nUntrusted {self.boundary}:\n{case.attacked_fixture}"
            if variant == BenchmarkVariant.ATTACKED
            else ""
        )
        return (
            f"Workflow: {self.workflow}\nTask: {case.task}\nUser request: {case.user_input}\n"
            f"Trusted fixture:\n{case.benign_fixture}{hostile}\n"
            f"Required facts: {', '.join(case.required_facts)}"
        )


class RAGDocumentHarness(ScenarioHarness):
    def __init__(self) -> None:
        super().__init__(BenchmarkScenario.RAG_DOCUMENT, "retrieved document", "RAG summarization")


class WebpageHarness(ScenarioHarness):
    def __init__(self) -> None:
        super().__init__(BenchmarkScenario.WEBPAGE, "page snapshot", "web research")


class GitHubIssueHarness(ScenarioHarness):
    def __init__(self) -> None:
        super().__init__(BenchmarkScenario.GITHUB_ISSUE, "issue or PR content", "coding-agent triage")


class EmailSupportHarness(ScenarioHarness):
    def __init__(self) -> None:
        super().__init__(BenchmarkScenario.EMAIL_SUPPORT, "customer message", "support response")


class ToolCallHarness(ScenarioHarness):
    def __init__(self) -> None:
        super().__init__(
            BenchmarkScenario.TOOL_CALL,
            "user instruction",
            "tool-calling task",
            inspect_attack_before_tool_use=False,
        )


HARNESSES: dict[BenchmarkScenario, ScenarioHarness] = {
    harness.scenario: harness
    for harness in (
        RAGDocumentHarness(),
        WebpageHarness(),
        GitHubIssueHarness(),
        EmailSupportHarness(),
        ToolCallHarness(),
    )
}


def harness_for(case: BenchmarkCase) -> ScenarioHarness:
    return HARNESSES[case.scenario]
