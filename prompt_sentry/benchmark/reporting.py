from __future__ import annotations

from pathlib import Path

from prompt_sentry.benchmark.models import BenchmarkReport

_SUMMARY_PATH = Path("docs/benchmark-results.md")


def write_summary(report: BenchmarkReport, path: Path = _SUMMARY_PATH) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_readme_summary(report), encoding="utf-8")
    return path


def render_readme_summary(report: BenchmarkReport) -> str:
    lines = [
        "# Benchmark results",
        "",
        f"Suite: `{report.benchmark_version}` — Mode: `{report.mode.value}` — "
        f"Seed: `{report.seed}` — Run: `{report.run_id}`",
        "",
        f"**Composite score: {report.composite_score:.2f} / 100**",
        "",
    ]
    if report.defense_comparison:
        lines.extend(
            [
                "## Defense comparison",
                "",
                "| Defense | Attack Success ↓ | Benign Task Success ↑ | "
                "False Positive ↓ | Median Latency ↓ | ASR Reduction |",
                "|---|---:|---:|---:|---:|---:|",
            ]
        )
        for row in report.defense_comparison:
            lines.append(
                f"| {row.defense_profile.value} | {row.attack_success_rate:.1%} | "
                f"{row.benign_task_success_rate:.1%} | {row.false_positive_rate:.1%} | "
                f"{row.median_defense_latency_ms:.0f} ms | {row.asr_reduction_vs_none:.1%} |"
            )
        lines.append("")
    if report.aggregates:
        lines.extend(
            [
                "## Protected vs unprotected",
                "",
                "| Protection | Attack Success ↓ | Secure Completion ↑ | "
                "Benign Completion ↑ | Tool Violations | Secret Leaks |",
                "|---|---:|---:|---:|---:|---:|",
            ]
        )
        for name, metrics in report.aggregates.items():
            lines.append(
                f"| {name} | {metrics.attack_success_rate:.1%} | "
                f"{metrics.secure_task_completion_rate:.1%} | "
                f"{metrics.benign_task_completion_rate:.1%} | "
                f"{metrics.tool_violation_rate:.1%} | {metrics.secret_leak_rate:.1%} |"
            )
        lines.append("")
    lines.extend(["## Acceptance gates", ""])
    for name, passed in report.acceptance.items():
        lines.append(f"- {'✓' if passed else '✗'} {name.replace('_', ' ')}")
    lines.append("")
    lines.append(
        "_Updated automatically by `promptsentry-benchmark run`. "
        "Do not edit by hand._"
    )
    lines.append("")
    return "\n".join(lines)


def write_reports(report: BenchmarkReport, directory: Path) -> tuple[Path, Path]:
    directory.mkdir(parents=True, exist_ok=True)
    stem = f"{report.benchmark_version}_{report.run_id}"
    json_path = directory / f"{stem}.json"
    markdown_path = directory / f"{stem}.md"
    if json_path.exists() or markdown_path.exists():
        raise FileExistsError(f"Benchmark artifacts already exist for run {report.run_id}")
    json_path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    markdown_path.write_text(render_markdown(report), encoding="utf-8")
    return json_path, markdown_path


def render_markdown(report: BenchmarkReport) -> str:
    lines = [
        f"# PromptSentry benchmark: {report.benchmark_version}",
        "",
        f"Run ID: `{report.run_id}`  ",
        f"Mode: `{report.mode.value}`  ",
        f"Protection: `{report.protection.value}`  ",
        f"Seed: `{report.seed}`  ",
        f"Composite score: **{report.composite_score:.2f}**",
        f"Latency overhead: `{report.latency_overhead_ms:.4f} ms`  ",
        f"Cost overhead: `${report.cost_overhead_usd:.6f}`",
        "",
    ]
    if report.defense_comparison:
        lines.extend(
            [
                "## Defense comparison",
                "",
                "| Defense | Attack Success ↓ | Benign Task Success ↑ | False Positive ↓ | Median Defense Latency ↓ |",
                "|---|---:|---:|---:|---:|",
            ]
        )
        for row in report.defense_comparison:
            lines.append(
                f"| {row.defense_profile.value} | {row.attack_success_rate:.1%} | "
                f"{row.benign_task_success_rate:.1%} | {row.false_positive_rate:.1%} | "
                f"{row.median_defense_latency_ms:.2f} ms |"
            )
        lines.extend(
            [
                "",
                "Latency for replayed LLM profiles combines measured local overhead with the "
                "captured Anthropic reference latency; no artificial delay is introduced.",
                "",
                "| Defense | Secure completion | Tool violations | Secret leaks | Detection recall | "
                "p95 defense latency | Cost | ASR reduction |",
                "|---|---:|---:|---:|---:|---:|---:|---:|",
            ]
        )
        for row in report.defense_comparison:
            lines.append(
                f"| {row.defense_profile.value} | {row.secure_task_completion_rate:.1%} | "
                f"{row.tool_violation_rate:.1%} | {row.secret_leak_rate:.1%} | "
                f"{row.detection_recall:.1%} | {row.p95_defense_latency_ms:.2f} ms | "
                f"${row.total_cost_usd:.6f} | {row.asr_reduction_vs_none:.1%} |"
            )
        lines.extend(
            [
                "",
                "## Scenario metrics",
                "",
                "| Scenario | Defense | ASR | Benign task success | False positive | Tool violations | Secret leaks |",
                "|---|---|---:|---:|---:|---:|---:|",
            ]
        )
        for scenario, profile_metrics in report.scenario_metrics.items():
            for profile, metrics in profile_metrics.items():
                lines.append(
                    f"| {scenario} | {profile} | {metrics.attack_success_rate:.1%} | "
                    f"{metrics.benign_task_completion_rate:.1%} | "
                    f"{metrics.false_positive_rate:.1%} | {metrics.tool_violation_rate:.1%} | "
                    f"{metrics.secret_leak_rate:.1%} |"
                )
    else:
        lines.extend(
            [
                "| Protection | ASR | Secure completion | Benign completion | "
                "Tool violations | Secret leaks | Detection recall |",
                "|---|---:|---:|---:|---:|---:|---:|",
            ]
        )
        for name, metrics in report.aggregates.items():
            lines.append(
                f"| {name} | {metrics.attack_success_rate:.1%} | "
                f"{metrics.secure_task_completion_rate:.1%} | "
                f"{metrics.benign_task_completion_rate:.1%} | "
                f"{metrics.tool_violation_rate:.1%} | {metrics.secret_leak_rate:.1%} | "
                f"{metrics.detection_recall:.1%} |"
            )
    lines.extend(["", "## Acceptance gates", ""])
    for name, passed in report.acceptance.items():
        lines.append(f"- {'PASS' if passed else 'FAIL'} — {name.replace('_', ' ')}")
    lines.extend(["", "## Per-case results", ""])
    lines.append("| Case | Scenario | Variant | Protection | Task complete | Attack success |")
    lines.append("|---|---|---|---|---:|---:|")
    for result in report.results:
        lines.append(
            f"| {result.case_id} | {result.scenario.value} | {result.variant.value} | "
            f"{result.protection} | {result.grade.task_completed} | {result.grade.attack_success} |"
        )
    return "\n".join(lines) + "\n"
