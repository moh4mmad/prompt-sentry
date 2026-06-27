from app.models.schemas import Action, Finding, Severity, Source

SEVERITY_ORDER = {
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}

UNTRUSTED_CONTENT_SOURCES = {
    Source.RETRIEVED_DOCUMENT,
    Source.WEBPAGE,
    Source.TOOL_OUTPUT,
    Source.MEMORY,
}


def max_finding_severity(findings: list[Finding]) -> Severity:
    return max((finding.severity for finding in findings), key=lambda severity: SEVERITY_ORDER[severity])


def should_audit(findings: list[Finding], action: Action) -> bool:
    return bool(findings) or action != Action.ALLOW
