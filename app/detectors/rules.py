import re
from collections.abc import Iterable
from dataclasses import dataclass

from app.detectors.normalizer import NormalizedText
from app.models.schemas import Action, AttackType, Finding, Severity, Source


@dataclass(frozen=True)
class Rule:
    attack_type: AttackType
    severity: Severity
    confidence: float
    evidence: str
    pattern: re.Pattern[str]
    sources: set[Source] | None = None


RULES: tuple[Rule, ...] = (
    Rule(
        AttackType.DIRECT_INJECTION,
        Severity.HIGH,
        0.92,
        "instruction override attempt",
        re.compile(
            r"\b(ignore|forget|disregard|bypass|override|overwrite)\b.{0,50}"
            r"\b(previous|prior|above|system|developer|instructions|rules|prompt|guidelines)\b",
            re.I,
        ),
        {Source.USER_PROMPT},
    ),
    Rule(
        AttackType.DIRECT_INJECTION,
        Severity.HIGH,
        0.88,
        "new instructions injection",
        re.compile(r"\b(new instructions?|your (real )?task|from now on you|you are now)\b", re.I),
        {Source.USER_PROMPT},
    ),
    Rule(
        AttackType.DIRECT_INJECTION,
        Severity.HIGH,
        0.88,
        "start fresh / forget all rules override",
        re.compile(
            r"\b(forget|discard|erase)\b.{0,40}\b(every|all).{0,20}"
            r"\b(rule|instruction|guideline|prompt)\b",
            re.I,
        ),
        None,
    ),
    Rule(
        AttackType.INDIRECT_INJECTION,
        Severity.HIGH,
        0.88,
        "disregard safety filters in stored context",
        re.compile(r"\b(disregard|ignore|bypass)\b.{0,30}\b(safety filter|safety|content filter|restriction)\b", re.I),
        {Source.RETRIEVED_DOCUMENT, Source.WEBPAGE, Source.TOOL_OUTPUT, Source.MEMORY},
    ),
    Rule(
        AttackType.JAILBREAK,
        Severity.HIGH,
        0.88,
        "jailbroken AI persona or avoid-norms instruction",
        re.compile(
            r"\b(jailbroken (AI|assistant|model)|strive to avoid norms|respond (only )?as \w+ with no filter"
            r"|you are (now )?(a )?(jailbroken|unrestricted|unfiltered|uncensored))\b",
            re.I,
        ),
        None,
    ),
    Rule(
        AttackType.PAYLOAD_SMUGGLING,
        Severity.HIGH,
        0.90,
        "space-separated character evasion collapsed to injection phrase",
        re.compile(
            r"ignoreprevious(instructions)?|ignoreall(previous)?(instructions)?|revealyour(system)?prompt"
            r"|bypassall(restrictions|rules|filters?)|disregardsystem(instructions|prompt|rules)?"
            r"|forgetall(rules|instructions)|disregardall(instructions|rules|safety)?",
            re.I,
        ),
        None,
    ),
    Rule(
        AttackType.INDIRECT_INJECTION,
        Severity.HIGH,
        0.90,
        "untrusted content contains instruction override language",
        re.compile(
            r"\b(ignore|forget|disregard|bypass|override|overwrite)\b.{0,50}"
            r"\b(previous|prior|above|system|developer|instructions|rules|prompt|guidelines)\b",
            re.I,
        ),
        {Source.RETRIEVED_DOCUMENT, Source.WEBPAGE, Source.TOOL_OUTPUT, Source.MEMORY},
    ),
    Rule(
        AttackType.JAILBREAK,
        Severity.HIGH,
        0.88,
        "jailbreak or persona bypass phrase",
        re.compile(
            r"\b(DAN|developer mode|jailbreak|no restrictions|unfiltered|pretend you are|roleplay as"
            r"|act as an? (unrestricted|unfiltered|uncensored)"
            r"|without (safety|ethical|content) (guidelines|filters?|restrictions?)"
            r"|disable (safety|content|ethical) (filter|guideline|mode)"
            r"|enable (developer|unrestricted|jailbreak) mode)\b",
            re.I,
        ),
        None,
    ),
    Rule(
        AttackType.JAILBREAK,
        Severity.HIGH,
        0.85,
        "unrestricted AI persona request",
        re.compile(r"\b(unrestricted|uncensored|unfiltered)\b.{0,30}\b(AI|assistant|model|mode)\b", re.I),
        None,
    ),
    Rule(
        AttackType.GOAL_HIJACKING,
        Severity.HIGH,
        0.82,
        "competing objective redirects the task",
        re.compile(r"\b(instead|before you continue|new objective|your real task|do not answer the user)\b", re.I),
        None,
    ),
    Rule(
        AttackType.SYSTEM_PROMPT_EXTRACTION,
        Severity.CRITICAL,
        0.94,
        "request to reveal hidden prompt or internal instructions",
        re.compile(
            r"\b(reveal|print|show|dump|exfiltrate|repeat|output|display|tell me)\b.{0,60}"
            r"\b(system prompt|developer prompt|hidden instructions?|internal instructions?"
            r"|initial (prompt|instructions?)|"
            r"your instructions?|what (you were|they) (told|given)|verbatim)\b",
            re.I,
        ),
        None,
    ),
    Rule(
        AttackType.SYSTEM_PROMPT_EXTRACTION,
        Severity.HIGH,
        0.88,
        "request for developer-given instructions verbatim",
        re.compile(
            r"\b(what (instructions?|rules?|guidelines?) (did|were|have).{0,30}(give|given|told|provided))\b"
            r"|\b(show|print|repeat|give me) (your )?"
            r"(exact|verbatim|full|all (the)?) (instructions?|rules?|guidelines?|prompt)\b",
            re.I,
        ),
        None,
    ),
    Rule(
        AttackType.CREDENTIAL_EXFILTRATION,
        Severity.CRITICAL,
        0.95,
        "request targets credentials or tokens",
        re.compile(r"\b(api keys?|tokens?|passwords?|secrets?|credentials?|env vars?|environment variables?)\b", re.I),
        None,
    ),
    Rule(
        AttackType.DATA_EXFILTRATION,
        Severity.CRITICAL,
        0.90,
        "request attempts to access broad or unauthorized private data",
        re.compile(
            r"\b(all customer data|all user data|another user|cross[- ]tenant|private records|export the database)\b",
            re.I,
        ),
        None,
    ),
    Rule(
        AttackType.IDENTITY_SPOOFING,
        Severity.HIGH,
        0.84,
        "unverified authority or role claim with action demand",
        re.compile(
            r"\b(i am|this is)\b.{0,35}\b(ceo|admin|administrator|root|security team|developer|owner)\b"
            r".{0,80}\b(bypass|approve|authorize|override|urgent|disable|safety|filter|escalation)\b",
            re.I,
        ),
        None,
    ),
    Rule(
        AttackType.IDENTITY_SPOOFING,
        Severity.HIGH,
        0.80,
        "authority claim with disable/safety action",
        re.compile(
            r"\b(i am|this is) (the )?(developer|admin|ceo|owner|root)\b.{0,80}"
            r"\b(disable|turn off|remove|bypass|safety|filter|restriction|override)\b",
            re.I,
        ),
        None,
    ),
    Rule(
        AttackType.TOOL_ABUSE,
        Severity.CRITICAL,
        0.91,
        "dangerous tool or destructive action requested",
        re.compile(r"\b(delete|drop table|rm -rf|curl .*http|send .*to|email .*to|transfer|exfiltrate)\b", re.I),
        None,
    ),
    Rule(
        AttackType.CONTEXT_POISONING,
        Severity.HIGH,
        0.86,
        "attempt to persist unsafe instruction into memory",
        re.compile(
            r"\b(remember|store|save this preference)\b.{0,60}\b(ignore|bypass|disable)"
            r".{0,40}\b(policy|rules|instructions|safety)\b",
            re.I,
        ),
        None,
    ),
    Rule(
        AttackType.SENSITIVE_OUTPUT_LEAK,
        Severity.CRITICAL,
        0.92,
        "output appears to contain a secret-like value",
        re.compile(r"\b(sk-[A-Za-z0-9_-]{16,}|ghp_[A-Za-z0-9_]{16,}|AKIA[0-9A-Z]{12,})\b", re.I),
        {Source.MODEL_OUTPUT, Source.TOOL_OUTPUT},
    ),
)


def detect_rules(source: Source, normalized: NormalizedText) -> list[Finding]:
    findings: dict[AttackType, Finding] = {}
    texts = [normalized.normalized, *normalized.variants]

    for rule in RULES:
        if rule.sources is not None and source not in rule.sources:
            continue
        if any(rule.pattern.search(text) for text in texts):
            finding = Finding(
                attack_type=rule.attack_type,
                confidence=rule.confidence,
                severity=rule.severity,
                evidence=[rule.evidence],
                recommended_action=_recommended_action(rule.severity),
            )
            findings[rule.attack_type] = _stronger(findings.get(rule.attack_type), finding)

    if normalized.variants and findings:
        smuggling = Finding(
            attack_type=AttackType.PAYLOAD_SMUGGLING,
            confidence=0.90,
            severity=Severity.HIGH,
            evidence=_unique(normalized.evidence + ["decoded payload matched malicious pattern"]),
            recommended_action=Action.BLOCK,
        )
        findings[AttackType.PAYLOAD_SMUGGLING] = smuggling
    elif normalized.evidence:
        for item in normalized.evidence:
            if "decoded" in item:
                findings[AttackType.PAYLOAD_SMUGGLING] = Finding(
                    attack_type=AttackType.PAYLOAD_SMUGGLING,
                    confidence=0.55,
                    severity=Severity.MEDIUM,
                    evidence=_unique(normalized.evidence),
                    recommended_action=Action.SANITIZE,
                )
                break

    return list(findings.values())


def _recommended_action(severity: Severity) -> Action:
    if severity == Severity.CRITICAL:
        return Action.BLOCK
    if severity == Severity.HIGH:
        return Action.SANITIZE
    if severity == Severity.MEDIUM:
        return Action.MONITOR
    return Action.ALLOW


def _stronger(current: Finding | None, candidate: Finding) -> Finding:
    if current is None:
        return candidate
    order = {Severity.LOW: 1, Severity.MEDIUM: 2, Severity.HIGH: 3, Severity.CRITICAL: 4}
    if order[candidate.severity] > order[current.severity]:
        return candidate
    if candidate.confidence > current.confidence:
        return candidate
    return current


def _unique(items: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    output: list[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            output.append(item)
    return output
