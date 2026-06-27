import json

from app.core.config import Settings
from app.core.decisions import max_finding_severity, should_audit
from app.logging.audit import AuditLogger
from app.models.schemas import (
    Action,
    AttackType,
    Finding,
    Severity,
    Source,
    ToolCallReviewRequest,
    ToolCallReviewResponse,
)
from app.scoring.risk import action_from_score, calculate_risk

RESTRICTED_ARGUMENT_TERMS = frozenset(
    {
        "api_key",
        "credential",
        "credentials",
        "customer_tokens",
        "password",
        "private",
        "secret",
        "secrets",
        "token",
        "tokens",
    }
)

DESTRUCTIVE_ARGUMENT_TERMS = frozenset(
    {
        "delete",
        "destroy",
        "drop",
        "email",
        "rm -rf",
        "send",
        "transfer",
        "truncate",
    }
)

UNTRUSTED_TOOL_TRIGGER_SOURCES = {
    Source.RETRIEVED_DOCUMENT,
    Source.WEBPAGE,
    Source.TOOL_OUTPUT,
}


class ToolCallPolicy:
    def __init__(self, settings: Settings, audit_logger: AuditLogger) -> None:
        self.settings = settings
        self.audit_logger = audit_logger

    def review(self, request: ToolCallReviewRequest) -> ToolCallReviewResponse:
        arguments_text = json.dumps(request.arguments, sort_keys=True).lower()
        findings = [
            *self._tool_scope_findings(request),
            *self._argument_findings(arguments_text),
            *self._trigger_source_findings(request),
        ]

        risk_score = calculate_risk(findings, Source.TOOL_OUTPUT) if findings else 0.05
        action = action_from_score(risk_score, self.settings)
        severity = max_finding_severity(findings) if findings else Severity.LOW
        reason = self._reason(findings)

        audit_event_id = None
        if should_audit(findings, action):
            audit_event_id = self.audit_logger.log(
                {
                    "request_id": request.request_id,
                    "tenant_id": request.tenant_id,
                    "user_id": request.user_id,
                    "session_id": request.session_id,
                    "source": "tool_call",
                    "tool_name": request.tool_name,
                    "risk_score": risk_score,
                    "severity": severity,
                    "action": action,
                    "reason": reason,
                    "attack_types": [finding.attack_type for finding in findings],
                    "findings": [finding.model_dump(mode="json") for finding in findings],
                },
                raw_text=json.dumps(request.arguments, sort_keys=True),
            )

        return ToolCallReviewResponse(
            request_id=request.request_id,
            action=action,
            risk_score=risk_score,
            severity=severity,
            reason=reason,
            findings=findings,
            audit_event_id=audit_event_id,
        )

    @staticmethod
    def _tool_scope_findings(request: ToolCallReviewRequest) -> list[Finding]:
        allowed_tools = request.metadata.allowed_tools
        if not allowed_tools or request.tool_name in allowed_tools:
            return []
        return [
            _finding(
                attack_type=AttackType.TOOL_ABUSE,
                confidence=0.96,
                severity=Severity.CRITICAL,
                evidence="tool is not allowed for user role",
            )
        ]

    @staticmethod
    def _argument_findings(arguments_text: str) -> list[Finding]:
        findings: list[Finding] = []
        if any(term in arguments_text for term in RESTRICTED_ARGUMENT_TERMS):
            findings.append(
                _finding(
                    attack_type=AttackType.DATA_EXFILTRATION,
                    confidence=0.92,
                    severity=Severity.CRITICAL,
                    evidence="tool arguments reference restricted or secret-like data",
                )
            )
        if any(term in arguments_text for term in DESTRUCTIVE_ARGUMENT_TERMS):
            findings.append(
                _finding(
                    attack_type=AttackType.TOOL_ABUSE,
                    confidence=0.86,
                    severity=Severity.HIGH,
                    evidence="tool arguments request destructive or external-send action",
                )
            )
        return findings

    @staticmethod
    def _trigger_source_findings(request: ToolCallReviewRequest) -> list[Finding]:
        if request.metadata.triggered_by_source not in UNTRUSTED_TOOL_TRIGGER_SOURCES:
            return []
        return [
            _finding(
                attack_type=AttackType.INDIRECT_INJECTION,
                confidence=0.80,
                severity=Severity.HIGH,
                evidence="tool call was triggered by untrusted content",
            )
        ]

    @staticmethod
    def _reason(findings: list[Finding]) -> str:
        if not findings:
            return "Tool call is allowed by current policy."
        return " ".join(f"{finding.evidence[0]}." for finding in findings if finding.evidence)


def _finding(attack_type: AttackType, confidence: float, severity: Severity, evidence: str) -> Finding:
    return Finding(
        attack_type=attack_type,
        confidence=confidence,
        severity=severity,
        evidence=[evidence],
        recommended_action=Action.BLOCK if severity == Severity.CRITICAL else Action.SANITIZE,
    )
