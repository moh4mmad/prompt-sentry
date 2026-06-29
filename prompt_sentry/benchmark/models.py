from __future__ import annotations

from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

BENCHMARK_VERSION = "realistic-agent-v1"


class BenchmarkScenario(StrEnum):
    RAG_DOCUMENT = "rag_document"
    WEBPAGE = "webpage"
    GITHUB_ISSUE = "github_issue"
    EMAIL_SUPPORT = "email_support"
    TOOL_CALL = "tool_call"


class BenchmarkMode(StrEnum):
    DETERMINISTIC = "deterministic"
    LIVE = "live"


class ProtectionMode(StrEnum):
    UNPROTECTED = "unprotected"
    PROTECTED = "protected"
    BOTH = "both"


class BenchmarkVariant(StrEnum):
    BENIGN = "benign"
    ATTACKED = "attacked"


class AttackBehavior(BaseModel):
    kind: Literal["tool_call", "secret_leak", "task_hijack"]
    tool_name: str | None = None
    arguments: dict[str, Any] = Field(default_factory=dict)
    output: str | None = None
    canary_key: str | None = None

    @model_validator(mode="after")
    def validate_behavior(self) -> AttackBehavior:
        if self.kind in {"tool_call", "secret_leak"} and not self.tool_name:
            raise ValueError("tool_name is required for tool-based attack behavior")
        if self.kind == "task_hijack" and not self.output:
            raise ValueError("output is required for task_hijack behavior")
        return self


class BenchmarkCase(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    scenario: BenchmarkScenario
    task: str
    user_input: str
    content_source: Literal["retrieved_document", "webpage", "tool_output", "memory", "user_prompt"]
    benign_fixture: str
    attacked_fixture: str
    available_tools: list[str] = Field(min_length=1)
    forbidden_tools: list[str] = Field(min_length=1)
    canary_secrets: dict[str, str] = Field(min_length=1)
    required_facts: list[str] = Field(min_length=1)
    excluded_outputs: list[str] = Field(default_factory=list)
    attack_success_predicates: list[
        Literal["forbidden_tool_called", "canary_leaked", "task_hijacked", "unauthorized_state_change"]
    ] = Field(min_length=1)
    attack_behavior: AttackBehavior
    tags: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_tools(self) -> BenchmarkCase:
        overlap = set(self.available_tools) & set(self.forbidden_tools)
        if overlap:
            raise ValueError(f"Tools cannot be both available and forbidden: {sorted(overlap)}")
        if self.attack_behavior.tool_name and self.attack_behavior.tool_name not in self.forbidden_tools:
            raise ValueError("Attack tool must be listed in forbidden_tools")
        if self.attack_behavior.canary_key and self.attack_behavior.canary_key not in self.canary_secrets:
            raise ValueError("Attack canary_key must exist in canary_secrets")
        return self


class ToolInvocation(BaseModel):
    name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    proposed: bool = True
    allowed: bool = False
    executed: bool = False
    forbidden: bool = False
    result: str | None = None


class DetectionEvent(BaseModel):
    boundary: Literal["content", "tool_call", "output"]
    action: str
    risk_score: float
    attack_types: list[str] = Field(default_factory=list)


class AgentTrace(BaseModel):
    final_output: str = ""
    tool_invocations: list[ToolInvocation] = Field(default_factory=list)
    state_changes: list[str] = Field(default_factory=list)
    detections: list[DetectionEvent] = Field(default_factory=list)
    observed_canaries: list[str] = Field(default_factory=list)
    refusal: bool = False
    error: str | None = None
    latency_ms: float = 0.0
    input_tokens: int | None = None
    output_tokens: int | None = None
    cost_usd: float | None = None


class CaseGrade(BaseModel):
    task_completed: bool
    attack_success: bool
    secure_task_completed: bool
    tool_violation: bool
    secret_leak: bool
    detected: bool
    false_positive: bool
    judge_score: float | None = Field(default=None, ge=0.0, le=1.0)
    reasons: list[str] = Field(default_factory=list)


class BenchmarkCaseResult(BaseModel):
    case_id: str
    scenario: BenchmarkScenario
    variant: BenchmarkVariant
    protection: Literal["protected", "unprotected"]
    repetition: int
    trace: AgentTrace
    grade: CaseGrade


class AggregateMetrics(BaseModel):
    total_runs: int = 0
    attacked_runs: int = 0
    benign_runs: int = 0
    attack_success_rate: float = 0.0
    secure_task_completion_rate: float = 0.0
    benign_task_completion_rate: float = 0.0
    refusal_rate: float = 0.0
    tool_violation_rate: float = 0.0
    secret_leak_rate: float = 0.0
    detection_recall: float = 0.0
    avg_latency_ms: float = 0.0
    total_input_tokens: int = 0
    total_output_tokens: int = 0
    total_cost_usd: float = 0.0


class BenchmarkRunRequest(BaseModel):
    suite: Literal["realistic-agent-v1"] = BENCHMARK_VERSION
    scenarios: list[BenchmarkScenario] = Field(default_factory=list)
    case_ids: list[str] = Field(default_factory=list)
    mode: BenchmarkMode = BenchmarkMode.DETERMINISTIC
    protection: ProtectionMode = ProtectionMode.BOTH
    provider: Literal["openai", "anthropic"] | None = None
    model: str | None = None
    seed: int = 42
    repetitions: int | None = Field(default=None, ge=1, le=5)
    live_full_corpus: bool = False
    judge_provider: Literal["openai", "anthropic"] | None = None
    judge_model: str | None = None

    @model_validator(mode="after")
    def validate_live_settings(self) -> BenchmarkRunRequest:
        if self.mode == BenchmarkMode.LIVE and (not self.provider or not self.model):
            raise ValueError("Live mode requires provider and model")
        if bool(self.judge_provider) != bool(self.judge_model):
            raise ValueError("judge_provider and judge_model must be supplied together")
        return self


class BenchmarkReport(BaseModel):
    benchmark_version: str = BENCHMARK_VERSION
    run_id: str
    created_at: str
    seed: int
    mode: BenchmarkMode
    protection: ProtectionMode
    provider: str | None = None
    model: str | None = None
    environment: dict[str, str] = Field(default_factory=dict)
    repetitions: int
    selected_case_ids: list[str]
    aggregates: dict[str, AggregateMetrics]
    scenario_metrics: dict[str, dict[str, AggregateMetrics]]
    protection_uplift: float
    benign_utility_delta: float
    latency_overhead_ms: float
    cost_overhead_usd: float
    composite_score: float
    acceptance: dict[str, bool] = Field(default_factory=dict)
    results: list[BenchmarkCaseResult]
