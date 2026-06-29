from collections import Counter
from pathlib import Path

import pytest

from app.core.config import Settings
from app.middleware.firewall import PromptSentry
from prompt_sentry.benchmark.grading import aggregate, composite, grade_trace
from prompt_sentry.benchmark.loader import load_cases, validate_corpus
from prompt_sentry.benchmark.models import (
    AgentTrace,
    AggregateMetrics,
    BenchmarkCaseResult,
    BenchmarkMode,
    BenchmarkRunRequest,
    BenchmarkScenario,
    BenchmarkVariant,
)
from prompt_sentry.benchmark.reporting import render_markdown, write_reports
from prompt_sentry.benchmark.runner import BenchmarkRunner


class NoopAudit:
    def log(self, event: dict, raw_text: str | None = None) -> None:
        return None


@pytest.fixture
def runner() -> BenchmarkRunner:
    firewall = PromptSentry(Settings(), audit_logger=NoopAudit())  # type: ignore[arg-type]
    return BenchmarkRunner(firewall)


def test_corpus_contains_exactly_ten_unique_pairs_per_scenario() -> None:
    cases = load_cases()
    assert len(cases) == 50
    assert len({case.id for case in cases}) == 50
    assert Counter(case.scenario for case in cases) == {scenario: 10 for scenario in BenchmarkScenario}
    for case in cases:
        assert case.benign_fixture
        assert case.attacked_fixture
        assert case.attack_success_predicates
        assert case.canary_secrets


def test_corpus_validation_rejects_incomplete_suite() -> None:
    with pytest.raises(ValueError, match="exactly 50"):
        validate_corpus(load_cases()[:-1])


def test_case_parser_reports_line_number(tmp_path: Path) -> None:
    malformed = tmp_path / "bad.jsonl"
    malformed.write_text("{not-json}\n", encoding="utf-8")
    with pytest.raises(ValueError, match=r"bad\.jsonl:1"):
        load_cases(malformed)


def test_live_sampling_is_seeded_and_balanced(runner: BenchmarkRunner) -> None:
    request = BenchmarkRunRequest(mode="live", provider="openai", model="mock", seed=17)
    first = runner.select_cases(request)
    second = runner.select_cases(request)
    assert [case.id for case in first] == [case.id for case in second]
    assert len(first) == 10
    assert Counter(case.scenario for case in first) == {scenario: 2 for scenario in BenchmarkScenario}
    full = runner.select_cases(request.model_copy(update={"live_full_corpus": True}))
    assert len(full) == 50


def test_filters_and_invalid_case_ids(runner: BenchmarkRunner) -> None:
    selected = runner.select_cases(
        BenchmarkRunRequest(scenarios=[BenchmarkScenario.WEBPAGE], case_ids=["web-03"])
    )
    assert [case.id for case in selected] == ["web-03"]
    with pytest.raises(ValueError, match="Unknown benchmark case IDs"):
        runner.select_cases(BenchmarkRunRequest(case_ids=["missing-case"]))
    with pytest.raises(ValueError, match="Live mode requires"):
        BenchmarkRunRequest(mode=BenchmarkMode.LIVE)


def test_grading_and_composite_formula() -> None:
    case = load_cases()[0]
    trace = AgentTrace(final_output="Task result: 09:14 UTC; 09:42 UTC")
    grade = grade_trace(case, BenchmarkVariant.BENIGN, trace)
    result = BenchmarkCaseResult(
        case_id=case.id,
        scenario=case.scenario,
        variant=BenchmarkVariant.BENIGN,
        protection="protected",
        repetition=1,
        trace=trace,
        grade=grade,
    )
    metrics = aggregate([result])
    assert metrics.benign_task_completion_rate == 1.0
    perfect = AggregateMetrics(
        secure_task_completion_rate=1,
        benign_task_completion_rate=1,
        detection_recall=1,
    )
    assert composite(perfect) == 100.0


def test_report_json_markdown_and_immutability(runner: BenchmarkRunner, tmp_path: Path) -> None:
    report = runner.run(BenchmarkRunRequest(case_ids=["tool-01"]))
    json_path, markdown_path = write_reports(report, tmp_path)
    assert json_path.exists()
    rendered_json = json_path.read_text(encoding="utf-8")
    assert report.run_id in rendered_json
    assert report.model_validate_json(rendered_json) == report
    markdown = markdown_path.read_text(encoding="utf-8")
    assert "Acceptance gates" in markdown
    assert "tool-01" in markdown
    assert render_markdown(report) == markdown
    with pytest.raises(FileExistsError):
        write_reports(report, tmp_path)
