from __future__ import annotations

from app.core.config import Settings
from app.models.schemas import Action, Finding, Severity, Source

SEVERITY_WEIGHTS = {
    Severity.LOW: 0.20,
    Severity.MEDIUM: 0.45,
    Severity.HIGH: 0.70,
    Severity.CRITICAL: 0.88,
}

SOURCE_BOOSTS = {
    Source.USER_PROMPT: 0.00,
    Source.RETRIEVED_DOCUMENT: 0.06,
    Source.WEBPAGE: 0.07,
    Source.TOOL_OUTPUT: 0.08,
    Source.MEMORY: 0.08,
    Source.MODEL_OUTPUT: 0.05,
}

# When any rule fires, the ensemble score may not fall below this floor.
_RULE_FIRE_FLOOR = 0.70


def calculate_risk(findings: list[Finding], source: Source) -> float:
    if not findings:
        return 0.05

    max_base = max(SEVERITY_WEIGHTS[finding.severity] for finding in findings)
    max_confidence = max(finding.confidence for finding in findings)
    multi_finding_boost = min(0.10, max(0, len(findings) - 1) * 0.03)
    score = max_base + (max_confidence * 0.12) + multi_finding_boost + SOURCE_BOOSTS[source]
    return round(min(1.0, score), 4)


def ensemble_risk(
    rule_score: float,
    llm_confidence: float,
    *,
    findings: list[Finding],
    settings: Settings,
) -> float:
    """Blend rule-based and LLM classifier scores.

    Hard floor: if any rule fired, the final score is at least _RULE_FIRE_FLOOR.
    """
    blended = (settings.rule_classifier_weight * rule_score) + (
        settings.llm_classifier_weight * llm_confidence
    )
    if findings:
        blended = max(blended, _RULE_FIRE_FLOOR)
    return round(min(1.0, blended), 4)


def severity_from_score(score: float) -> Severity:
    if score >= 0.90:
        return Severity.CRITICAL
    if score >= 0.75:
        return Severity.HIGH
    if score >= 0.50:
        return Severity.MEDIUM
    return Severity.LOW


def action_from_score(score: float, settings: Settings) -> Action:
    if settings.prompt_sentry_mode == "monitor":
        return Action.MONITOR if score >= settings.risk_monitor_threshold else Action.ALLOW
    if score >= settings.risk_alert_threshold:
        return Action.ALERT
    if score >= settings.risk_block_threshold:
        return Action.BLOCK
    if score >= settings.risk_sanitize_threshold:
        return Action.SANITIZE
    if score >= settings.risk_monitor_threshold:
        return Action.MONITOR
    return Action.ALLOW
