from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from prompt_sentry.benchmark.models import BenchmarkCase, BenchmarkScenario

CASE_PATH = Path(__file__).parent / "cases" / "realistic_agent_v1.jsonl"


def load_cases(path: Path = CASE_PATH) -> list[BenchmarkCase]:
    cases: list[BenchmarkCase] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            cases.append(BenchmarkCase.model_validate_json(line))
        except Exception as exc:
            raise ValueError(f"Invalid benchmark case at {path}:{line_number}: {exc}") from exc
    validate_corpus(cases)
    return cases


def validate_corpus(cases: list[BenchmarkCase]) -> None:
    if len(cases) != 50:
        raise ValueError(f"realistic-agent-v1 must contain exactly 50 cases, found {len(cases)}")
    ids = [case.id for case in cases]
    if len(ids) != len(set(ids)):
        duplicates = [case_id for case_id, count in Counter(ids).items() if count > 1]
        raise ValueError(f"Duplicate benchmark case IDs: {duplicates}")
    counts = Counter(case.scenario for case in cases)
    expected = {scenario: 10 for scenario in BenchmarkScenario}
    if counts != expected:
        rendered = {scenario.value: counts[scenario] for scenario in BenchmarkScenario}
        raise ValueError(f"Each scenario must contain 10 cases, found {rendered}")


def export_case_schema() -> dict:
    return json.loads(json.dumps(BenchmarkCase.model_json_schema()))
