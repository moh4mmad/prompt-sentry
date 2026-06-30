from __future__ import annotations

import argparse
from pathlib import Path

from app.core.config import Settings
from app.middleware.firewall import PromptSentry
from prompt_sentry.benchmark.loader import load_cases
from prompt_sentry.benchmark.models import BENCHMARK_V2, BENCHMARK_VERSION, BenchmarkRunRequest, DefenseProfile
from prompt_sentry.benchmark.replay import SNAPSHOT_PATH, capture_anthropic_snapshot, snapshot_json
from prompt_sentry.benchmark.reporting import write_reports, write_summary
from prompt_sentry.benchmark.runner import BenchmarkRunner


class _NoopAuditLogger:
    def log(self, event: dict, raw_text: str | None = None) -> None:
        return None


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="promptsentry-benchmark")
    commands = parser.add_subparsers(dest="command", required=True)
    validate = commands.add_parser("validate", help="Validate a benchmark corpus")
    validate.add_argument("--suite", choices=[BENCHMARK_VERSION, BENCHMARK_V2], default=BENCHMARK_VERSION)
    run = commands.add_parser("run", help="Run the realistic agent benchmark")
    run.add_argument("--suite", choices=[BENCHMARK_VERSION, BENCHMARK_V2], default=BENCHMARK_VERSION)
    run.add_argument("--scenario", action="append", default=[])
    run.add_argument("--case", dest="case_ids", action="append", default=[])
    run.add_argument("--mode", choices=["deterministic", "live"], default="deterministic")
    run.add_argument("--protection", choices=["protected", "unprotected", "both"])
    run.add_argument("--profile", action="append", choices=[profile.value for profile in DefenseProfile], default=[])
    run.add_argument("--compare-defenses", action="store_true")
    run.add_argument("--provider", choices=["openai", "anthropic"])
    run.add_argument("--model")
    run.add_argument("--seed", type=int, default=42)
    run.add_argument("--repetitions", type=int)
    run.add_argument("--live-full-corpus", action="store_true")
    run.add_argument("--judge-provider", choices=["openai", "anthropic"])
    run.add_argument("--judge-model")
    run.add_argument("--report-dir", type=Path, default=Path("benchmark-reports"))
    run.add_argument("--enforce-gates", action="store_true")
    capture = commands.add_parser("capture-llm-snapshot", help="Capture live Anthropic classifier decisions")
    capture.add_argument("--suite", choices=[BENCHMARK_V2], default=BENCHMARK_V2)
    capture.add_argument("--model", required=True)
    capture.add_argument("--output", type=Path, default=SNAPSHOT_PATH)
    capture.add_argument("--confirm-live", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "validate":
        cases = load_cases(suite=args.suite)
        print(f"{args.suite}: valid ({len(cases)} paired cases)")
        return 0
    if args.command == "capture-llm-snapshot":
        if not args.confirm_live:
            print("benchmark error: --confirm-live is required for paid snapshot capture")
            return 2
        if args.output.exists():
            print(f"benchmark error: snapshot already exists: {args.output}")
            return 2
        try:
            snapshot = capture_anthropic_snapshot(load_cases(suite=args.suite), model=args.model)
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(snapshot_json(snapshot), encoding="utf-8")
        except (ValueError, RuntimeError, OSError) as exc:
            print(f"benchmark error: {exc}")
            return 2
        print(f"captured {len(snapshot.decisions)} decisions to {args.output}")
        return 0
    try:
        profiles = list(DefenseProfile) if args.compare_defenses else args.profile
        request_data = dict(
            suite=args.suite,
            scenarios=args.scenario,
            case_ids=args.case_ids,
            mode=args.mode,
            defense_profiles=profiles,
            provider=args.provider,
            model=args.model,
            seed=args.seed,
            repetitions=args.repetitions,
            live_full_corpus=args.live_full_corpus,
            judge_provider=args.judge_provider,
            judge_model=args.judge_model,
        )
        if args.protection is not None:
            request_data["protection"] = args.protection
        if profiles and args.suite != BENCHMARK_V2:
            request_data["suite"] = BENCHMARK_V2 if args.compare_defenses else args.suite
        request = BenchmarkRunRequest(**request_data)
        report = BenchmarkRunner(PromptSentry(Settings(), audit_logger=_NoopAuditLogger())).run(request)  # type: ignore[arg-type]
        json_path, markdown_path = write_reports(report, args.report_dir)
        summary_path = write_summary(report)
    except (ValueError, RuntimeError, OSError) as exc:
        print(f"benchmark error: {exc}")
        return 2
    print(f"composite={report.composite_score:.2f} json={json_path} markdown={markdown_path} summary={summary_path}")
    if args.enforce_gates and not all(report.acceptance.values()):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
