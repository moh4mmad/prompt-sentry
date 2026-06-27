from app.core.config import Settings
from app.core.decisions import UNTRUSTED_CONTENT_SOURCES, max_finding_severity, should_audit
from app.detectors.normalizer import normalize_text
from app.detectors.rules import detect_rules
from app.logging.audit import AuditLogger
from app.models.schemas import Action, SecurityRequest, SecurityResponse
from app.sanitizers.text import sanitize_text
from app.scoring.risk import action_from_score, calculate_risk, ensemble_risk, severity_from_score


class InspectionService:
    def __init__(self, settings: Settings, audit_logger: AuditLogger) -> None:
        self.settings = settings
        self.audit_logger = audit_logger

    def inspect(self, request: SecurityRequest) -> SecurityResponse:
        normalized = normalize_text(request.text)
        findings = detect_rules(request.source, normalized)
        rule_score = calculate_risk(findings, request.source)

        risk_score = rule_score
        if self.settings.llm_classifier_enabled:
            from app.detectors.llm_classifier import classify

            llm_result = classify(request.text, settings=self.settings)
            if llm_result is not None:
                risk_score = ensemble_risk(
                    rule_score,
                    llm_result.confidence,
                    findings=findings,
                    settings=self.settings,
                )

        action = action_from_score(risk_score, self.settings)
        severity = max_finding_severity(findings) if findings else severity_from_score(risk_score)
        sanitized_text = self._sanitized_text(request, action)

        audit_event_id = None
        if should_audit(findings, action):
            audit_event_id = self.audit_logger.log(
                {
                    "request_id": request.request_id,
                    "tenant_id": request.tenant_id,
                    "user_id": request.user_id,
                    "session_id": request.session_id,
                    "source": request.source,
                    "risk_score": risk_score,
                    "severity": severity,
                    "action": action,
                    "attack_types": [finding.attack_type for finding in findings],
                    "findings": [finding.model_dump(mode="json") for finding in findings],
                },
                raw_text=request.text,
            )

        return SecurityResponse(
            request_id=request.request_id,
            action=action,
            risk_score=risk_score,
            severity=severity,
            sanitized_text=sanitized_text,
            findings=findings,
            audit_event_id=audit_event_id,
        )

    @staticmethod
    def _sanitized_text(request: SecurityRequest, action: Action) -> str | None:
        if action in {Action.BLOCK, Action.ALERT}:
            return None
        if action == Action.SANITIZE or request.source in UNTRUSTED_CONTENT_SOURCES:
            return sanitize_text(request.text, request.source)
        return request.text
