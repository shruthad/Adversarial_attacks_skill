from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any


def build_summary(results: list[dict[str, Any]], metadata: dict[str, Any] | None = None) -> dict[str, Any]:
    metadata = metadata or {}
    failed = [result for result in results if result.get("overall_status") == "failed"]
    passed = [result for result in results if result.get("overall_status") == "passed"]
    review = [result for result in results if result.get("requires_human_review")]
    critical = [result for result in failed if result.get("severity") == "critical"]
    return {
        "total_attack_surfaces_found": metadata.get("total_attack_surfaces_found", 0),
        "total_seed_tests_generated": metadata.get("total_seed_tests_generated", 0),
        "deepteam_variants_generated": metadata.get("deepteam_variants_generated", 0),
        "accepted_tests": metadata.get("accepted_tests", len(results)),
        "rejected_tests": metadata.get("rejected_tests", 0),
        "duplicate_tests_removed": metadata.get("duplicate_tests_removed", 0),
        "tests_executed": len(results),
        "passed_tests": len(passed),
        "failed_tests": len(failed),
        "failures_by_vulnerability": dict(Counter(result.get("vulnerability") or result.get("test_case", {}).get("vulnerability") for result in failed)),
        "failures_by_attack_strategy": dict(Counter(result.get("attack_strategy") or result.get("test_case", {}).get("attack_strategy") for result in failed)),
        "failures_by_agent": dict(Counter(result.get("failed_component") for result in failed if result.get("failed_component"))),
        "failures_by_tool": metadata.get("failures_by_tool", {}),
        "critical_findings": critical,
        "guardrail_false_positives": _count_named_failure(results, "guardrail false positive"),
        "guardrail_false_negatives": _count_named_failure(results, "guardrail false negative"),
        "tests_requiring_human_review": len(review),
        "regression_tests_created": metadata.get("regression_tests_created", 0),
        "fixed_regression_tests": metadata.get("fixed_regression_tests", 0),
        "still_failing_regression_tests": metadata.get("still_failing_regression_tests", 0),
    }


def generate_markdown_report(results: list[dict[str, Any]], output_path: str, metadata: dict[str, Any] | None = None) -> str:
    summary = build_summary(results, metadata)
    lines = [
        "# Agent Adversarial Evaluation Report",
        "",
        "## Summary",
        "",
        f"- Attack surfaces found: {summary['total_attack_surfaces_found']}",
        f"- Seed tests generated: {summary['total_seed_tests_generated']}",
        f"- DeepTeam variants generated: {summary['deepteam_variants_generated']}",
        f"- Tests executed: {summary['tests_executed']}",
        f"- Passed: {summary['passed_tests']}",
        f"- Failed: {summary['failed_tests']}",
        f"- Requires human review: {summary['tests_requiring_human_review']}",
        "",
        "## Critical Findings",
        "",
    ]
    if summary["critical_findings"]:
        for finding in summary["critical_findings"]:
            lines.append(f"- `{finding.get('test_case_id')}`: {finding.get('root_cause')}")
    else:
        lines.append("- None detected.")
    lines.extend(
        [
            "",
            "## Failure Breakdown",
            "",
            f"- By vulnerability: `{json.dumps(summary['failures_by_vulnerability'], sort_keys=True)}`",
            f"- By attack strategy: `{json.dumps(summary['failures_by_attack_strategy'], sort_keys=True)}`",
            f"- By failed component: `{json.dumps(summary['failures_by_agent'], sort_keys=True)}`",
            "",
            "## Guardrails",
            "",
            f"- False positives: {summary['guardrail_false_positives']}",
            f"- False negatives: {summary['guardrail_false_negatives']}",
            "",
            "## Regression",
            "",
            f"- Regression tests created: {summary['regression_tests_created']}",
            f"- Fixed regression tests: {summary['fixed_regression_tests']}",
            f"- Still-failing regression tests: {summary['still_failing_regression_tests']}",
            "",
            "Human review is required before saving failures as regression tests or testing new targets.",
        ]
    )
    markdown = "\n".join(lines) + "\n"
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(markdown, encoding="utf-8")
    return markdown


def generate_json_report(results: list[dict[str, Any]], output_path: str, metadata: dict[str, Any] | None = None) -> dict[str, Any]:
    report = {"summary": build_summary(results, metadata), "results": results}
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    return report


def generate_regression_comparison_report(results: list[dict[str, Any]], output_path: str) -> str:
    fixed = [item for item in results if item.get("status") == "Fixed"]
    still = [item for item in results if item.get("status") == "Still failing"]
    review = [item for item in results if item.get("status") == "Requires review"]
    markdown = "\n".join(
        [
            "# Regression Comparison Report",
            "",
            f"- Fixed regression tests: {len(fixed)}",
            f"- Still-failing regression tests: {len(still)}",
            f"- Requires review: {len(review)}",
            "",
        ]
    )
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(markdown, encoding="utf-8")
    return markdown


def _count_named_failure(results: list[dict[str, Any]], phrase: str) -> int:
    count = 0
    for result in results:
        for deterministic in result.get("deterministic_results", []):
            if phrase in str(deterministic.get("reason", "")).lower():
                count += 1
    return count
