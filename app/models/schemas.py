from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class Source(StrEnum):
    USER_PROMPT = "user_prompt"
    RETRIEVED_DOCUMENT = "retrieved_document"
    WEBPAGE = "webpage"
    TOOL_OUTPUT = "tool_output"
    MEMORY = "memory"
    MODEL_OUTPUT = "model_output"


class Action(StrEnum):
    ALLOW = "allow"
    MONITOR = "monitor"
    SANITIZE = "sanitize"
    BLOCK = "block"
    ALERT = "alert"


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AttackType(StrEnum):
    DIRECT_INJECTION = "direct_injection"
    INDIRECT_INJECTION = "indirect_injection"
    JAILBREAK = "jailbreak"
    GOAL_HIJACKING = "goal_hijacking"
    PAYLOAD_SMUGGLING = "payload_smuggling"
    SYSTEM_PROMPT_EXTRACTION = "system_prompt_extraction"
    CREDENTIAL_EXFILTRATION = "credential_exfiltration"
    TOOL_ABUSE = "tool_abuse"
    IDENTITY_SPOOFING = "identity_spoofing"
    DATA_EXFILTRATION = "data_exfiltration"
    CONTEXT_POISONING = "context_poisoning"
    SENSITIVE_OUTPUT_LEAK = "sensitive_output_leak"


class RequestMetadata(BaseModel):
    model_config = ConfigDict(extra="allow")

    model: str | None = None
    user_role: str | None = None
    allowed_tools: list[str] = Field(default_factory=list)
    allowed_data_scopes: list[str] = Field(default_factory=list)
    document_id: str | None = None
    document_url: str | None = None
    retrieval_rank: int | None = None
    tool_name: str | None = None
    triggered_by_source: Source | None = None


class SecurityRequest(BaseModel):
    request_id: str
    tenant_id: str | None = None
    user_id: str | None = None
    session_id: str | None = None
    source: Source
    text: str = Field(min_length=1)
    metadata: RequestMetadata = Field(default_factory=RequestMetadata)


class Finding(BaseModel):
    attack_type: AttackType
    confidence: float = Field(ge=0.0, le=1.0)
    severity: Severity
    evidence: list[str] = Field(default_factory=list)
    recommended_action: Action


class SecurityResponse(BaseModel):
    request_id: str
    action: Action
    risk_score: float = Field(ge=0.0, le=1.0)
    severity: Severity
    sanitized_text: str | None = None
    findings: list[Finding] = Field(default_factory=list)
    audit_event_id: str | None = None


class ToolCallMetadata(BaseModel):
    model_config = ConfigDict(extra="allow")

    user_role: str | None = None
    allowed_tools: list[str] = Field(default_factory=list)
    allowed_data_scopes: list[str] = Field(default_factory=list)
    triggered_by_source: Source | None = None


class ToolCallReviewRequest(BaseModel):
    request_id: str
    tenant_id: str | None = None
    user_id: str | None = None
    session_id: str | None = None
    tool_name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    metadata: ToolCallMetadata = Field(default_factory=ToolCallMetadata)


class ToolCallReviewResponse(BaseModel):
    request_id: str
    action: Action
    risk_score: float = Field(ge=0.0, le=1.0)
    severity: Severity
    reason: str
    findings: list[Finding] = Field(default_factory=list)
    audit_event_id: str | None = None


class RedTeamRunRequest(BaseModel):
    suite: str = "default"
    categories: list[AttackType] = Field(default_factory=list)
    mode: str = "offline"


class RedTeamFailure(BaseModel):
    test_id: str
    category: AttackType
    expected_action: Action
    actual_action: Action
    risk_score: float = Field(ge=0.0, le=1.0)


class RedTeamRunResponse(BaseModel):
    suite: str
    total_tests: int
    passed: int
    failed: int
    pass_rate: float = Field(ge=0.0, le=1.0)
    missed_attack_types: list[AttackType] = Field(default_factory=list)
    report_id: str
    failures: list[RedTeamFailure] = Field(default_factory=list)
