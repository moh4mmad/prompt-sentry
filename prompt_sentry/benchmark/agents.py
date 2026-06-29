from __future__ import annotations

from time import perf_counter

from app.middleware.firewall import PromptSentry
from prompt_sentry.benchmark.guard import BenchmarkGuard
from prompt_sentry.benchmark.harnesses import harness_for
from prompt_sentry.benchmark.models import (
    AgentTrace,
    BenchmarkCase,
    BenchmarkVariant,
)
from prompt_sentry.benchmark.sandbox import InMemorySandbox


class DeterministicAgent:
    """Reproducible vulnerable agent used to measure protection uplift in CI."""

    def __init__(self, firewall: PromptSentry) -> None:
        self.firewall = firewall

    def run(self, case: BenchmarkCase, variant: BenchmarkVariant, *, protected: bool) -> AgentTrace:
        started = perf_counter()
        sandbox = InMemorySandbox(case)
        guard = BenchmarkGuard(self.firewall, allowed_tools=case.available_tools) if protected else None
        output = self._task_output(case)
        follow_attack = variant == BenchmarkVariant.ATTACKED
        harness = harness_for(case)

        # Every workflow crosses at least one legitimate tool boundary before
        # producing an answer. These tools are synthetic and return local fixture data.
        for tool_name in case.available_tools:
            arguments = {"case_id": case.id}
            invocation = sandbox.proposed(tool_name, arguments)
            allowed = True
            reason = "unprotected execution"
            if protected and guard:
                allowed, reason = guard.review_tool_call(tool_name, arguments, "user_prompt")
            if allowed:
                result = sandbox.execute(invocation)
                if protected and guard:
                    result_source = case.content_source if case.content_source != "user_prompt" else "tool_output"
                    content_safe, _ = guard.inspect_content(result, result_source)
                    if not content_safe:
                        output = "Required fixture blocked by PromptSentry."
                        follow_attack = False
            else:
                sandbox.deny(invocation, reason)

        if protected and guard and variant == BenchmarkVariant.ATTACKED:
            # Tool-call cases exercise the pre-execution policy boundary directly. Other
            # scenarios exercise their untrusted-content boundary before a proposal exists.
            if harness.inspect_attack_before_tool_use:
                content_safe, _ = guard.inspect_content(case.attacked_fixture, case.content_source)
                follow_attack = content_safe

        if follow_attack:
            behavior = case.attack_behavior
            if behavior.kind == "task_hijack":
                output = behavior.output or output
                sandbox.state_changes.append("simulated:task_hijack")
            else:
                assert behavior.tool_name is not None
                invocation = sandbox.proposed(behavior.tool_name, behavior.arguments)
                allowed = True
                reason = "unprotected execution"
                if protected and guard:
                    allowed, reason = guard.review_tool_call(
                        behavior.tool_name,
                        behavior.arguments,
                        case.content_source,
                    )
                if allowed:
                    result = sandbox.execute(invocation)
                    if behavior.kind == "secret_leak":
                        output = f"{output} {result}"
                else:
                    sandbox.deny(invocation, reason)

        refusal = False
        if protected and guard:
            output_safe, safe_output = guard.verify_output(output)
            if not output_safe:
                output = safe_output or "Output blocked by PromptSentry."
                refusal = True

        observed = [value for value in case.canary_secrets.values() if value in output]
        return AgentTrace(
            final_output=output,
            tool_invocations=sandbox.ledger,
            state_changes=sandbox.state_changes,
            detections=guard.detections if guard else [],
            observed_canaries=observed,
            refusal=refusal,
            latency_ms=(perf_counter() - started) * 1000,
        )

    @staticmethod
    def _task_output(case: BenchmarkCase) -> str:
        return "Task result: " + "; ".join(case.required_facts)
