from __future__ import annotations

from uuid import uuid4

from app.middleware.firewall import PromptSentry
from app.models.schemas import (
    Action,
    RequestMetadata,
    SecurityRequest,
    Source,
    ToolCallMetadata,
    ToolCallReviewRequest,
)
from prompt_sentry.benchmark.models import DetectionEvent


class BenchmarkGuard:
    """In-process adapter for the same policies exposed by the PromptSentry API."""

    def __init__(self, firewall: PromptSentry, *, allowed_tools: list[str]) -> None:
        self.firewall = firewall
        self.allowed_tools = allowed_tools
        self.detections: list[DetectionEvent] = []

    def inspect_content(self, text: str, source: str) -> tuple[bool, str]:
        response = self.firewall.inspect(
            SecurityRequest(
                request_id=f"bench_{uuid4().hex}",
                source=Source(source),
                text=text,
                metadata=RequestMetadata(allowed_tools=self.allowed_tools),
            )
        )
        self._record("content", response.action, response.risk_score, response.findings)
        safe = response.action not in {Action.SANITIZE, Action.BLOCK, Action.ALERT}
        return safe, response.sanitized_text or ""

    def review_tool_call(self, name: str, arguments: dict, source: str) -> tuple[bool, str]:
        response = self.firewall.review_tool_call(
            ToolCallReviewRequest(
                request_id=f"bench_tool_{uuid4().hex}",
                tool_name=name,
                arguments=arguments,
                metadata=ToolCallMetadata(
                    allowed_tools=self.allowed_tools,
                    triggered_by_source=Source(source),
                ),
            )
        )
        self._record("tool_call", response.action, response.risk_score, response.findings)
        return response.action not in {Action.SANITIZE, Action.BLOCK, Action.ALERT}, response.reason

    def verify_output(self, text: str) -> tuple[bool, str]:
        response = self.firewall.inspect(
            SecurityRequest(
                request_id=f"bench_output_{uuid4().hex}",
                source=Source.MODEL_OUTPUT,
                text=text,
            )
        )
        self._record("output", response.action, response.risk_score, response.findings)
        safe = response.action not in {Action.SANITIZE, Action.BLOCK, Action.ALERT}
        return safe, response.sanitized_text or ""

    def _record(self, boundary: str, action: Action, risk_score: float, findings: list) -> None:
        if findings or action != Action.ALLOW:
            self.detections.append(
                DetectionEvent(
                    boundary=boundary,
                    action=action.value,
                    risk_score=risk_score,
                    attack_types=[finding.attack_type.value for finding in findings],
                )
            )
