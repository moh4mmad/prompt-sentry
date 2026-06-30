from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from time import perf_counter
from typing import Any

from app.middleware.firewall import PromptSentry
from app.models.schemas import Action, RequestMetadata, SecurityRequest, Source
from app.scoring.risk import action_from_score, ensemble_risk
from prompt_sentry.benchmark.guard import BenchmarkGuard
from prompt_sentry.benchmark.models import DefenseProfile, DetectionEvent
from prompt_sentry.benchmark.replay import ClassifierDecision, ClassifierReplay

_KEYWORD_MANIFEST = json.loads(
    (Path(__file__).parent / "data" / "keyword_filter_v1.json").read_text(encoding="utf-8")
)
KEYWORD_FILTER_VERSION = str(_KEYWORD_MANIFEST["version"])
KEYWORD_PHRASES = tuple(str(phrase) for phrase in _KEYWORD_MANIFEST["phrases"])


@dataclass(frozen=True)
class ProfileCapabilities:
    keywords: bool = False
    rules: bool = False
    llm: bool = False
    tool_policy: bool = False
    output_verification: bool = False


PROFILE_CAPABILITIES = {
    DefenseProfile.NONE: ProfileCapabilities(),
    DefenseProfile.KEYWORD_FILTER: ProfileCapabilities(keywords=True),
    DefenseProfile.LLM_JUDGE: ProfileCapabilities(llm=True),
    DefenseProfile.RULES_ONLY: ProfileCapabilities(rules=True),
    DefenseProfile.RULES_LLM: ProfileCapabilities(rules=True, llm=True),
    DefenseProfile.RULES_TOOL_POLICY: ProfileCapabilities(rules=True, tool_policy=True),
    DefenseProfile.RULES_OUTPUT_VERIFICATION: ProfileCapabilities(
        rules=True, output_verification=True
    ),
    DefenseProfile.FULL_STACK: ProfileCapabilities(
        rules=True,
        llm=True,
        tool_policy=True,
        output_verification=True,
    ),
}


class ProfileGuard:
    def __init__(
        self,
        firewall: PromptSentry,
        profile: DefenseProfile,
        *,
        allowed_tools: list[str],
        replay: ClassifierReplay | None,
    ) -> None:
        self.firewall = firewall
        rule_settings = firewall.settings.model_copy(update={"llm_classifier_enabled": False})
        self.rule_firewall = PromptSentry(rule_settings, audit_logger=firewall.audit_logger)
        self.profile = profile
        self.capabilities = PROFILE_CAPABILITIES[profile]
        self.rules_guard = BenchmarkGuard(self.rule_firewall, allowed_tools=allowed_tools)
        self.replay = replay
        self.detections: list[DetectionEvent] = []
        self.defense_latency_ms = 0.0
        self.reference_latency_ms = 0.0
        self.cost_usd = 0.0

    def inspect_content(self, text: str, source: str) -> tuple[bool, str]:
        started = perf_counter()
        if self.capabilities.keywords:
            match = next((phrase for phrase in KEYWORD_PHRASES if phrase in text.casefold()), None)
            if match:
                self.detections.append(
                    DetectionEvent(
                        boundary="content",
                        action="block",
                        risk_score=1.0,
                        attack_types=[f"keyword:{match}"],
                    )
                )
                self.defense_latency_ms += (perf_counter() - started) * 1000
                return False, ""

        rule_response = None
        if self.capabilities.rules:
            rule_response = self.rule_firewall.inspect(
                SecurityRequest(
                    request_id="benchmark-profile-content",
                    source=Source(source),
                    text=text,
                    metadata=RequestMetadata(),
                )
            )

        llm_decision = self._llm_decision(text, source) if self.capabilities.llm else None
        action, score, attack_types = self._content_action(rule_response, llm_decision)
        if action != Action.ALLOW or attack_types:
            self.detections.append(
                DetectionEvent(
                    boundary="content",
                    action=action.value,
                    risk_score=score,
                    attack_types=attack_types,
                )
            )
        self.defense_latency_ms += (perf_counter() - started) * 1000
        safe = action not in {Action.SANITIZE, Action.BLOCK, Action.ALERT}
        cleaned = rule_response.sanitized_text if rule_response is not None else text
        return safe, cleaned or ""

    def review_tool_call(self, name: str, arguments: dict[str, Any], source: str) -> tuple[bool, str]:
        if not self.capabilities.tool_policy:
            return True, "Tool policy is disabled for this defense profile."
        started = perf_counter()
        allowed, reason = self.rules_guard.review_tool_call(name, arguments, source)
        self.defense_latency_ms += (perf_counter() - started) * 1000
        self.detections.extend(self.rules_guard.detections)
        self.rules_guard.detections.clear()
        return allowed, reason

    def verify_output(self, text: str) -> tuple[bool, str]:
        if not self.capabilities.output_verification:
            return True, text
        started = perf_counter()
        safe, cleaned = self.rules_guard.verify_output(text)
        self.defense_latency_ms += (perf_counter() - started) * 1000
        self.detections.extend(self.rules_guard.detections)
        self.rules_guard.detections.clear()
        return safe, cleaned

    def _llm_decision(self, text: str, source: str) -> ClassifierDecision:
        if self.replay is None:
            raise ValueError(f"Defense profile {self.profile.value} requires a classifier replay")
        decision = self.replay.lookup(text, source)
        self.reference_latency_ms += decision.latency_ms
        self.cost_usd += decision.cost_usd
        return decision

    def _content_action(self, rule_response, llm_decision: ClassifierDecision | None):
        if rule_response is None and llm_decision is None:
            return Action.ALLOW, 0.0, []
        if rule_response is None:
            assert llm_decision is not None
            score = llm_decision.confidence if llm_decision.attack_type else 0.05
            return (
                action_from_score(score, self.firewall.settings),
                score,
                [llm_decision.attack_type] if llm_decision.attack_type else [],
            )
        attack_types = [finding.attack_type.value for finding in rule_response.findings]
        score = rule_response.risk_score
        if llm_decision is not None:
            score = ensemble_risk(
                score,
                llm_decision.confidence if llm_decision.attack_type else 0.0,
                findings=rule_response.findings,
                settings=self.firewall.settings,
            )
            if llm_decision.attack_type and llm_decision.attack_type not in attack_types:
                attack_types.append(llm_decision.attack_type)
        return action_from_score(score, self.firewall.settings), score, attack_types

    @property
    def effective_latency_ms(self) -> float:
        if self.profile == DefenseProfile.NONE:
            return 0.0
        return self.defense_latency_ms + self.reference_latency_ms

    @property
    def latency_source(self) -> str:
        if self.profile == DefenseProfile.NONE:
            return "none"
        if self.reference_latency_ms and self.replay is not None:
            return self.replay.latency_source
        return "measured"
