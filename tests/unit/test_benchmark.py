from collections import Counter
from pathlib import Path

import pytest

from app.core.config import Settings
from app.middleware.firewall import PromptSentry
from prompt_sentry.benchmark.grading import aggregate, composite, grade_trace
from prompt_sentry.benchmark.loader import load_cases, validate_corpus
from prompt_sentry.benchmark.models import (
    BENCHMARK_V2,
    AgentTrace,
    AggregateMetrics,
    AttackStratum,
    BenchmarkCaseResult,
    BenchmarkMode,
    BenchmarkRunRequest,
    BenchmarkScenario,
    BenchmarkVariant,
    DefenseProfile,
)
from prompt_sentry.benchmark.profiles import KEYWORD_FILTER_VERSION, PROFILE_CAPABILITIES
from prompt_sentry.benchmark.replay import (
    ClassifierDecision,
    ClassifierReplay,
    ClassifierSnapshot,
    LiveAnthropicClassifier,
    capture_anthropic_snapshot,
    classifier_inputs,
    classifier_prompt_hash,
    content_hash,
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


def test_v2_corpus_is_balanced_by_scenario_and_stratum() -> None:
    cases = load_cases(suite=BENCHMARK_V2)
    assert len(cases) == 50
    for scenario in BenchmarkScenario:
        selected = [case for case in cases if case.scenario == scenario]
        assert Counter(case.attack_stratum for case in selected) == {
            stratum: 2 for stratum in AttackStratum
        }
    assert sum(case.benign_keyword_collision for case in cases) == 5


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
    with pytest.raises(ValueError, match="cannot be supplied together"):
        BenchmarkRunRequest(
            suite=BENCHMARK_V2,
            protection="both",
            defense_profiles=[DefenseProfile.NONE],
        )


def test_defense_profile_capabilities_are_explicit() -> None:
    assert KEYWORD_FILTER_VERSION == "keyword-filter-v1"
    assert PROFILE_CAPABILITIES[DefenseProfile.NONE].rules is False
    assert PROFILE_CAPABILITIES[DefenseProfile.RULES_ONLY].rules is True
    assert PROFILE_CAPABILITIES[DefenseProfile.RULES_TOOL_POLICY].tool_policy is True
    assert PROFILE_CAPABILITIES[DefenseProfile.RULES_OUTPUT_VERIFICATION].output_verification is True
    assert PROFILE_CAPABILITIES[DefenseProfile.FULL_STACK].llm is True


def test_rules_only_forces_llm_classifier_off(monkeypatch) -> None:
    calls = 0

    def classify(*args, **kwargs):
        nonlocal calls
        calls += 1
        raise AssertionError("rules-only profile called the LLM classifier")

    monkeypatch.setattr("app.detectors.llm_classifier.classify", classify)
    firewall = PromptSentry(
        Settings(llm_classifier_enabled=True),
        audit_logger=NoopAudit(),  # type: ignore[arg-type]
    )
    runner = BenchmarkRunner(firewall)
    runner.run(
        BenchmarkRunRequest(
            suite=BENCHMARK_V2,
            case_ids=["v2-rag-01"],
            defense_profiles=[DefenseProfile.RULES_ONLY],
        )
    )
    assert calls == 0


def make_replay() -> ClassifierReplay:
    cases = load_cases(suite=BENCHMARK_V2)
    attacked_hashes = {
        content_hash(case.attacked_fixture, case.content_source)
        for case in cases
        if case.attack_surface == "content"
    }
    decisions = []
    for text, source in classifier_inputs(cases):
        key = content_hash(text, source)
        attacked = key in attacked_hashes
        decisions.append(
            ClassifierDecision(
                content_hash=key,
                source=source,
                attack_type="indirect_injection" if attacked else None,
                confidence=0.95 if attacked else 0.05,
                latency_ms=500.0,
                input_tokens=20,
                output_tokens=5,
                cost_usd=0.0001,
            )
        )
    return ClassifierReplay(
        ClassifierSnapshot(
            provider="anthropic",
            model="mock-reference",
            classifier_prompt_sha256=classifier_prompt_hash(),
            created_at="2026-01-01T00:00:00+00:00",
            capture_kind="live",
            decisions=decisions,
        )
    )


def test_classifier_replay_validates_hashes() -> None:
    replay = make_replay()
    replay.validate_inputs(classifier_inputs(load_cases(suite=BENCHMARK_V2)))
    with pytest.raises(ValueError, match="missing content hash"):
        replay.lookup("changed fixture", "webpage")


def test_mocked_anthropic_snapshot_capture() -> None:
    from types import SimpleNamespace

    class Messages:
        def create(self, **kwargs):
            return SimpleNamespace(
                content=[
                    SimpleNamespace(
                        text='{"attack_type": null, "confidence": 0.05, "reasoning": "benign"}'
                    )
                ],
                usage=SimpleNamespace(input_tokens=10, output_tokens=4),
            )

    snapshot = capture_anthropic_snapshot(
        load_cases(suite=BENCHMARK_V2)[:1],
        model="mock-anthropic",
        client=SimpleNamespace(messages=Messages()),
    )
    assert snapshot.provider == "anthropic"
    assert snapshot.capture_kind == "live"
    assert snapshot.decisions
    assert snapshot.decisions[0].input_tokens == 10


def test_replay_rejects_stale_prompt_hash() -> None:
    with pytest.raises(ValueError, match="prompt hash is stale"):
        ClassifierReplay(
            ClassifierSnapshot(
                provider="anthropic",
                model="stale",
                classifier_prompt_sha256="0" * 64,
                created_at="2026-01-01T00:00:00+00:00",
                capture_kind="live",
                decisions=[],
            )
        )


def test_live_classifier_propagates_provider_failure() -> None:
    from types import SimpleNamespace

    class BrokenMessages:
        def create(self, **kwargs):
            raise RuntimeError("classifier unavailable")

    classifier = LiveAnthropicClassifier(
        model="broken",
        client=SimpleNamespace(messages=BrokenMessages()),
    )
    with pytest.raises(RuntimeError, match="classifier unavailable"):
        classifier.lookup("hello", "webpage")


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
