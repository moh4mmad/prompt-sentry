from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from prompt_sentry.benchmark.models import (
    BENCHMARK_V2,
    BENCHMARK_VERSION,
    AttackStratum,
    AttackSurface,
    BenchmarkCase,
    BenchmarkScenario,
)

CASE_PATH = Path(__file__).parent / "cases" / "realistic_agent_v1.jsonl"
CASE_PATHS = {
    BENCHMARK_VERSION: CASE_PATH,
    BENCHMARK_V2: Path(__file__).parent / "cases" / "realistic_agent_v2.jsonl",
}


def load_cases(path: Path | None = None, *, suite: str = BENCHMARK_VERSION) -> list[BenchmarkCase]:
    path = path or CASE_PATHS.get(suite)
    if path is None:
        raise ValueError(f"Unknown benchmark suite: {suite}")
    cases: list[BenchmarkCase] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            cases.append(BenchmarkCase.model_validate_json(line))
        except Exception as exc:
            raise ValueError(f"Invalid benchmark case at {path}:{line_number}: {exc}") from exc
    validate_corpus(cases, suite=suite if path == CASE_PATHS.get(suite) else None)
    return cases


def validate_corpus(cases: list[BenchmarkCase], *, suite: str | None = BENCHMARK_VERSION) -> None:
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
    if suite == BENCHMARK_V2:
        missing = [case.id for case in cases if case.attack_stratum is None or case.attack_surface is None]
        if missing:
            raise ValueError(f"v2 cases require attack stratum and surface: {missing}")
        invalid_layers = [
            case.id
            for case in cases
            if case.attack_stratum not in case.expected_defense_layers
        ]
        if invalid_layers:
            raise ValueError(f"v2 expected defense layers are incomplete: {invalid_layers}")
        expected_surfaces = {
            AttackStratum.KEYWORD: AttackSurface.CONTENT,
            AttackStratum.RULES: AttackSurface.CONTENT,
            AttackStratum.LLM: AttackSurface.CONTENT,
            AttackStratum.TOOL_POLICY: AttackSurface.TOOL_CALL,
            AttackStratum.OUTPUT_VERIFICATION: AttackSurface.OUTPUT,
        }
        invalid_surfaces = [
            case.id
            for case in cases
            if case.attack_surface != expected_surfaces[case.attack_stratum]
        ]
        if invalid_surfaces:
            raise ValueError(f"v2 attack surfaces do not match their strata: {invalid_surfaces}")
        for scenario in BenchmarkScenario:
            strata = Counter(case.attack_stratum for case in cases if case.scenario == scenario)
            expected_strata = {stratum: 2 for stratum in AttackStratum}
            if strata != expected_strata:
                rendered = {stratum.value: strata[stratum] for stratum in AttackStratum}
                raise ValueError(f"Each v2 scenario must contain two cases per stratum, found {rendered}")
        if sum(case.benign_keyword_collision for case in cases) != 5:
            raise ValueError("v2 must contain exactly five benign keyword-collision cases")


def export_case_schema() -> dict:
    return json.loads(json.dumps(BenchmarkCase.model_json_schema()))
