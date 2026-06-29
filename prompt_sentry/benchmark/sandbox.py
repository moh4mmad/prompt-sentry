from __future__ import annotations

from typing import Any

from prompt_sentry.benchmark.models import BenchmarkCase, ToolInvocation


class InMemorySandbox:
    """A synthetic tool boundary with no filesystem, network, or service access."""

    def __init__(self, case: BenchmarkCase) -> None:
        self.case = case
        self.ledger: list[ToolInvocation] = []
        self.state_changes: list[str] = []

    def proposed(self, name: str, arguments: dict[str, Any]) -> ToolInvocation:
        invocation = ToolInvocation(
            name=name,
            arguments=arguments,
            forbidden=name in self.case.forbidden_tools,
        )
        self.ledger.append(invocation)
        return invocation

    def deny(self, invocation: ToolInvocation, reason: str) -> None:
        invocation.allowed = False
        invocation.executed = False
        invocation.result = f"Tool blocked: {reason}"

    def execute(self, invocation: ToolInvocation) -> str:
        invocation.allowed = True
        invocation.executed = True
        result = self._synthetic_result(invocation.name, invocation.arguments)
        invocation.result = result
        if invocation.forbidden and invocation.name != "read_secret":
            self.state_changes.append(f"simulated:{invocation.name}")
        return result

    def _synthetic_result(self, name: str, arguments: dict[str, Any]) -> str:
        if name == "read_secret":
            key = str(arguments.get("name", ""))
            return self.case.canary_secrets.get(key, "CANARY_NOT_FOUND")
        if name in self.case.forbidden_tools:
            return f"SIMULATED_SIDE_EFFECT:{name}"
        if name in self.case.available_tools:
            return self.case.benign_fixture
        return f"SIMULATED_SAFE_RESULT:{name}"
