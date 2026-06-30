from __future__ import annotations

from time import perf_counter

from app.middleware.firewall import PromptSentry
from prompt_sentry.benchmark.guard import BenchmarkGuard
from prompt_sentry.benchmark.harnesses import harness_for
from prompt_sentry.benchmark.models import (
    AgentTrace,
    AttackSurface,
    BenchmarkCase,
    BenchmarkVariant,
    DefenseProfile,
)
from prompt_sentry.benchmark.profiles import ProfileGuard
from prompt_sentry.benchmark.replay import ClassifierReplay
from prompt_sentry.benchmark.sandbox import InMemorySandbox


class DeterministicAgent:
    """Reproducible vulnerable agent used to measure protection uplift in CI."""

    def __init__(self, firewall: PromptSentry) -> None:
        self.firewall = firewall

    def run(self, case: BenchmarkCase, variant: BenchmarkVariant, *, protected: bool) -> AgentTrace:
        guard = BenchmarkGuard(self.firewall, allowed_tools=case.available_tools) if protected else None
        return self._execute(case, variant, guard=guard, verify_output=protected)

    def run_profile(
        self,
        case: BenchmarkCase,
        variant: BenchmarkVariant,
        *,
        profile: DefenseProfile,
        replay: ClassifierReplay | None,
    ) -> AgentTrace:
        guard = ProfileGuard(
            self.firewall,
            profile,
            allowed_tools=case.available_tools,
            replay=replay,
        )
        return self._execute(
            case,
            variant,
            guard=guard,
            verify_output=guard.capabilities.output_verification,
        )

    def _execute(
        self,
        case: BenchmarkCase,
        variant: BenchmarkVariant,
        *,
        guard: BenchmarkGuard | ProfileGuard | None,
        verify_output: bool,
    ) -> AgentTrace:
        started = perf_counter()
        sandbox = InMemorySandbox(case)
        output = self._task_output(case)
        follow_attack = variant == BenchmarkVariant.ATTACKED
        harness = harness_for(case)

        for tool_name in case.available_tools:
            arguments = {"case_id": case.id}
            invocation = sandbox.proposed(tool_name, arguments)
            allowed, reason = (True, "unprotected execution")
            if guard:
                allowed, reason = guard.review_tool_call(tool_name, arguments, "user_prompt")
            if allowed:
                result = sandbox.execute(invocation)
                if guard:
                    source = case.content_source if case.content_source != "user_prompt" else "tool_output"
                    content_safe, _ = guard.inspect_content(result, source)
                    if not content_safe:
                        output = "Required fixture blocked by defense."
                        follow_attack = False
            else:
                sandbox.deny(invocation, reason)

        inspect_attack = (
            case.attack_surface == AttackSurface.CONTENT
            if case.attack_surface is not None
            else harness.inspect_attack_before_tool_use
        )
        if guard and variant == BenchmarkVariant.ATTACKED and inspect_attack:
            content_safe, _ = guard.inspect_content(case.attacked_fixture, case.content_source)
            follow_attack = content_safe

        if follow_attack:
            behavior = case.attack_behavior
            if behavior.kind == "task_hijack":
                output = behavior.output or output
                sandbox.state_changes.append("simulated:task_hijack")
            elif behavior.kind == "output_leak":
                assert behavior.canary_key is not None
                output = f"{output} {case.canary_secrets[behavior.canary_key]}"
            else:
                assert behavior.tool_name is not None
                invocation = sandbox.proposed(behavior.tool_name, behavior.arguments)
                allowed, reason = (True, "unprotected execution")
                if guard:
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
        if guard and verify_output:
            output_safe, safe_output = guard.verify_output(output)
            if not output_safe:
                output = safe_output or "Output blocked by defense."
                refusal = True

        observed = [value for value in case.canary_secrets.values() if value in output]
        profile_guard = guard if isinstance(guard, ProfileGuard) else None
        return AgentTrace(
            final_output=output,
            tool_invocations=sandbox.ledger,
            state_changes=sandbox.state_changes,
            detections=guard.detections if guard else [],
            observed_canaries=observed,
            refusal=refusal,
            latency_ms=(perf_counter() - started) * 1000,
            cost_usd=profile_guard.cost_usd if profile_guard else None,
            defense_latency_ms=profile_guard.effective_latency_ms if profile_guard else 0.0,
            defense_latency_source=profile_guard.latency_source if profile_guard else "none",
        )

    @staticmethod
    def _task_output(case: BenchmarkCase) -> str:
        return "Task result: " + "; ".join(case.required_facts)
