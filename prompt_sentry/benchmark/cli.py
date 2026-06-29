from __future__ import annotations

import argparse
from pathlib import Path

from app.core.config import Settings
from app.middleware.firewall import PromptSentry
from prompt_sentry.benchmark.loader import load_cases
from prompt_sentry.benchmark.models import BenchmarkRunRequest
from prompt_sentry.benchmark.reporting import write_reports
from prompt_sentry.benchmark.runner import BenchmarkRunner


class _NoopAuditLogger:
    def log(self, event: dict, raw_text: str | None = None) -> None:
        return None


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="promptsentry-benchmark")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("validate", help="Validate the realistic-agent-v1 corpus")
    run = commands.add_parser("run", help="Run the realistic agent benchmark")
    run.add_argument("--scenario", action="append", default=[])
    run.add_argument("--case", dest="case_ids", action="append", default=[])
    run.add_argument("--mode", choices=["deterministic", "live"], default="deterministic")
    run.add_argument("--protection", choices=["protected", "unprotected", "both"], default="both")
    run.add_argument("--provider", choices=["openai", "anthropic"])
    run.add_argument("--model")
    run.add_argument("--seed", type=int, default=42)
    run.add_argument("--repetitions", type=int)
    run.add_argument("--live-full-corpus", action="store_true")
    run.add_argument("--judge-provider", choices=["openai", "anthropic"])
    run.add_argument("--judge-model")
    run.add_argument("--report-dir", type=Path, default=Path("benchmark-reports"))
    run.add_argument("--enforce-gates", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "validate":
        cases = load_cases()
        print(f"realistic-agent-v1: valid ({len(cases)} paired cases)")
        return 0
    try:
        request = BenchmarkRunRequest(
            scenarios=args.scenario,
            case_ids=args.case_ids,
            mode=args.mode,
            protection=args.protection,
            provider=args.provider,
            model=args.model,
            seed=args.seed,
            repetitions=args.repetitions,
            live_full_corpus=args.live_full_corpus,
            judge_provider=args.judge_provider,
            judge_model=args.judge_model,
        )
        report = BenchmarkRunner(PromptSentry(Settings(), audit_logger=_NoopAuditLogger())).run(request)  # type: ignore[arg-type]
        json_path, markdown_path = write_reports(report, args.report_dir)
    except (ValueError, RuntimeError, OSError) as exc:
        print(f"benchmark error: {exc}")
        return 2
    print(f"composite={report.composite_score:.2f} json={json_path} markdown={markdown_path}")
    if args.enforce_gates and not all(report.acceptance.values()):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
