from __future__ import annotations

from pathlib import Path

from prompt_sentry.benchmark.models import BenchmarkReport


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
        "| Protection | ASR | Secure completion | Benign completion | "
        "Tool violations | Secret leaks | Detection recall |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
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
