from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from time import perf_counter

from pydantic import BaseModel, ConfigDict, Field

from app.detectors.llm_classifier import _SYSTEM_PROMPT, _parse
from prompt_sentry.benchmark.models import BENCHMARK_V2

SNAPSHOT_PATH = Path(__file__).parent / "snapshots" / "anthropic_realistic_agent_v2.json"


def content_hash(text: str, source: str) -> str:
    return hashlib.sha256(f"{source}\0{text}".encode()).hexdigest()


def classifier_prompt_hash() -> str:
    return hashlib.sha256(_SYSTEM_PROMPT.encode()).hexdigest()


class ClassifierDecision(BaseModel):
    content_hash: str
    source: str
    attack_type: str | None = None
    confidence: float = Field(ge=0.0, le=1.0)
    latency_ms: float = Field(ge=0.0)
    input_tokens: int = Field(default=0, ge=0)
    output_tokens: int = Field(default=0, ge=0)
    cost_usd: float = Field(default=0.0, ge=0.0)


class ClassifierSnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid")

    snapshot_version: str = "classifier-replay-v1"
    suite: str = BENCHMARK_V2
    provider: str
    model: str
    classifier_prompt_sha256: str
    created_at: str
    capture_kind: str = "live"
    decisions: list[ClassifierDecision]


class ClassifierReplay:
    latency_source = "reference_snapshot"
    def __init__(self, snapshot: ClassifierSnapshot) -> None:
        if snapshot.suite != BENCHMARK_V2:
            raise ValueError(f"Classifier snapshot suite must be {BENCHMARK_V2}")
        if snapshot.classifier_prompt_sha256 != classifier_prompt_hash():
            raise ValueError("Classifier snapshot prompt hash is stale")
        if snapshot.capture_kind != "live":
            raise ValueError("Classifier replay requires a live-captured snapshot")
        self.snapshot = snapshot
        self._decisions = {decision.content_hash: decision for decision in snapshot.decisions}
        if len(self._decisions) != len(snapshot.decisions):
            raise ValueError("Classifier snapshot contains duplicate content hashes")

    @classmethod
    def load(cls, path: Path = SNAPSHOT_PATH) -> ClassifierReplay:
        return cls(ClassifierSnapshot.model_validate_json(path.read_text(encoding="utf-8")))

    def lookup(self, text: str, source: str) -> ClassifierDecision:
        key = content_hash(text, source)
        try:
            return self._decisions[key]
        except KeyError as exc:
            raise ValueError(f"Classifier snapshot is missing content hash {key}") from exc

    def validate_inputs(self, inputs: list[tuple[str, str]]) -> None:
        expected = {content_hash(text, source) for text, source in inputs}
        missing = expected - self._decisions.keys()
        if missing:
            raise ValueError(f"Classifier snapshot is missing {len(missing)} required decisions")


class LiveAnthropicClassifier:
    latency_source = "measured"
    def __init__(self, *, model: str, client=None) -> None:
        if client is None:
            try:
                from anthropic import Anthropic
            except ImportError as exc:
                raise RuntimeError("Install prompt-sentry[anthropic-agent] for live comparison") from exc
            client = Anthropic()
        self.model = model
        self.client = client
        self.snapshot = ClassifierSnapshot(
            provider="anthropic",
            model=model,
            classifier_prompt_sha256=classifier_prompt_hash(),
            created_at=datetime.now(UTC).isoformat(),
            capture_kind="live",
            decisions=[],
        )

    def lookup(self, text: str, source: str) -> ClassifierDecision:
        return _anthropic_decision(self.client, self.model, text, source)

    def validate_inputs(self, inputs: list[tuple[str, str]]) -> None:
        return None


def snapshot_json(snapshot: ClassifierSnapshot) -> str:
    return json.dumps(snapshot.model_dump(mode="json"), indent=2, sort_keys=True) + "\n"


def classifier_inputs(cases) -> list[tuple[str, str]]:
    from prompt_sentry.benchmark.models import AttackSurface

    inputs: dict[str, tuple[str, str]] = {}
    for case in cases:
        source = case.content_source if case.content_source != "user_prompt" else "tool_output"
        inputs[content_hash(case.benign_fixture, source)] = (case.benign_fixture, source)
        if case.attack_surface == AttackSurface.CONTENT:
            inputs[content_hash(case.attacked_fixture, case.content_source)] = (
                case.attacked_fixture,
                case.content_source,
            )
    return list(inputs.values())


def capture_anthropic_snapshot(cases, *, model: str, client=None) -> ClassifierSnapshot:
    if client is None:
        try:
            from anthropic import Anthropic
        except ImportError as exc:
            raise RuntimeError("Install prompt-sentry[anthropic-agent] to capture a snapshot") from exc
        client = Anthropic()
    decisions: list[ClassifierDecision] = []
    for text, source in classifier_inputs(cases):
        decisions.append(_anthropic_decision(client, model, text, source))
    return ClassifierSnapshot(
        provider="anthropic",
        model=model,
        classifier_prompt_sha256=classifier_prompt_hash(),
        created_at=datetime.now(UTC).isoformat(),
        capture_kind="live",
        decisions=decisions,
    )


def _anthropic_decision(client, model: str, text: str, source: str) -> ClassifierDecision:
    started = perf_counter()
    response = client.messages.create(
        model=model,
        max_tokens=256,
        system=_SYSTEM_PROMPT,
        messages=[{"role": "user", "content": text[:4000]}],
    )
    latency_ms = (perf_counter() - started) * 1000
    parsed = _parse(response.content[0].text)
    if parsed is None:
        raise ValueError("Anthropic classifier returned an invalid decision")
    usage = getattr(response, "usage", None)
    return ClassifierDecision(
        content_hash=content_hash(text, source),
        source=source,
        attack_type=parsed.attack_type.value if parsed.attack_type else None,
        confidence=parsed.confidence,
        latency_ms=latency_ms,
        input_tokens=int(getattr(usage, "input_tokens", 0) or 0),
        output_tokens=int(getattr(usage, "output_tokens", 0) or 0),
    )
