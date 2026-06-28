from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import StrEnum
from typing import Any


class Action(StrEnum):
    ALLOW = "allow"
    MONITOR = "monitor"
    SANITIZE = "sanitize"
    BLOCK = "block"
    ALERT = "alert"

    @property
    def denied(self) -> bool:
        return self in {Action.BLOCK, Action.ALERT}


@dataclass(frozen=True)
class SecurityContext:
    tenant_id: str | None = None
    user_id: str | None = None
    session_id: str | None = None
    agent_run_id: str | None = None
    framework: str | None = None
    model: str | None = None
    task: str | None = None
    tool_call_id: str | None = None
    user_role: str | None = None
    allowed_tools: tuple[str, ...] = ()
    allowed_data_scopes: tuple[str, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)

    def with_updates(self, **changes: Any) -> SecurityContext:
        return replace(self, **changes)

    def request_metadata(self) -> dict[str, Any]:
        values = {
            "agent_run_id": self.agent_run_id,
            "framework": self.framework,
            "model": self.model,
            "task": self.task,
            "tool_call_id": self.tool_call_id,
            "user_role": self.user_role,
            "allowed_tools": list(self.allowed_tools),
            "allowed_data_scopes": list(self.allowed_data_scopes),
            **self.metadata,
        }
        return {key: value for key, value in values.items() if value is not None}


@dataclass(frozen=True)
class InspectionResult:
    request_id: str
    action: Action
    risk_score: float
    severity: str
    sanitized_text: str | None
    findings: tuple[dict[str, Any], ...] = ()
    audit_event_id: str | None = None

    @property
    def denied(self) -> bool:
        return self.action.denied

    @property
    def attack_types(self) -> tuple[str, ...]:
        return tuple(str(finding.get("attack_type", "unknown")) for finding in self.findings)


@dataclass(frozen=True)
class ToolReviewResult:
    request_id: str
    action: Action
    risk_score: float
    severity: str
    reason: str
    findings: tuple[dict[str, Any], ...] = ()
    audit_event_id: str | None = None

    @property
    def denied(self) -> bool:
        return self.action.denied
