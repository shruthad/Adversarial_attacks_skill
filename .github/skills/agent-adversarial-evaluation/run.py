from __future__ import annotations

import argparse
import json
from pathlib import Path

from evaluator import aggregate_evaluation, deterministic_trace_evaluators, llm_judge_stub
from reporter import generate_json_report, generate_markdown_report, generate_regression_comparison_report
from skill import (
    DeepTeamRunner,
    TestCase,
    build_vulnerability_targets,
    deduplicate_tests,
    ensure_target_allowed,
    generate_seed_tests,
    load_runtime_config,
    load_system_profile,
    mocked_target_callback,
    read_jsonl,
    require_api_key,
    resolve_vulnerability_scope,
    run_async,
    run_regression_tests,
    validate_test_case,
    write_jsonl,
)


OUTPUT = Path("output")


def main() -> None:
    parser = argparse.ArgumentParser(description="Agent adversarial evaluation skill CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    generate = subparsers.add_parser("generate")
    generate.add_argument("--profile", default="target_profile.yaml")
    generate.add_argument("--vulnerabilities", nargs="*", default=[])
    generate.add_argument("--tests-per-vulnerability", type=int, default=3)
    generate.add_argument("--seed-templates", default="seed_templates.yaml")
    generate.add_argument("--deepteam-baseline", action="store_true")
    generate.add_argument("--runtime-config", default="runtime_config.yaml")

    expand = subparsers.add_parser("expand")
    expand.add_argument("--tests", required=True)
    expand.add_argument("--strategies", nargs="+", required=True)
    expand.add_argument("--variants-per-strategy", type=int, default=1)
    expand.add_argument("--runtime-config", default="runtime_config.yaml")

    execute = subparsers.add_parser("execute")
    execute.add_argument("--tests", required=True)
    execute.add_argument("--profile", default="target_profile.yaml")
    execute.add_argument("--target", required=True)

    evaluate = subparsers.add_parser("evaluate")
    evaluate.add_argument("--results", required=True)
    evaluate.add_argument("--profile", default="target_profile.yaml")
    evaluate.add_argument("--llm-judge", action="store_true")
    evaluate.add_argument("--runtime-config", default="runtime_config.yaml")

    regression = subparsers.add_parser("regression")
    regression.add_argument("--tests", required=True)
    regression.add_argument("--target", required=True)
    regression.add_argument("--profile", default="target_profile.yaml")

    report = subparsers.add_parser("report")
    report.add_argument("--results", required=True)

    args = parser.parse_args()
    OUTPUT.mkdir(exist_ok=True)

    if args.command == "generate":
        profile = load_system_profile(args.profile)
        vulnerabilities = resolve_vulnerability_scope(profile, args.vulnerabilities)
        targets = build_vulnerability_targets(profile, vulnerabilities)
        tests = generate_seed_tests(profile, targets, args.tests_per_vulnerability, args.seed_templates)
        if args.deepteam_baseline:
            runtime_config = load_runtime_config(args.runtime_config)
            runner = DeepTeamRunner(runtime_config)
            baseline_tests = runner.generate_baseline_seed_tests(profile, targets, args.tests_per_vulnerability)
            if runner.last_baseline_error:
                print(f"DeepTeam baseline generation skipped: {runner.last_baseline_error}")
            tests.extend(baseline_tests)
            tests = deduplicate_tests(tests)
        validated = [test for test in tests if validate_test_case(test, profile).passed]
        write_jsonl(OUTPUT / "seed_tests.jsonl", [test.model_dump() for test in validated])
        print(f"Generated {len(validated)} seed tests. Wrote output/seed_tests.jsonl")

    elif args.command == "expand":
        tests = [TestCase.model_validate(record) for record in read_jsonl(args.tests)]
        runtime_config = load_runtime_config(args.runtime_config)
        runner = DeepTeamRunner(runtime_config)
        expanded = runner.expand_tests(tests, args.strategies, args.variants_per_strategy)
        deduped = deduplicate_tests(expanded)
        write_jsonl(OUTPUT / "generated_tests.jsonl", [test.model_dump() for test in deduped])
        print(f"Expanded to {len(deduped)} generated tests. Wrote output/generated_tests.jsonl")

    elif args.command == "execute":
        profile = load_system_profile(args.profile)
        ensure_target_allowed(profile, args.target)
        tests = [TestCase.model_validate(record) for record in read_jsonl(args.tests)]
        results = run_async(DeepTeamRunner().execute_tests(tests, mocked_target_callback))
        write_jsonl(OUTPUT / "execution_results.jsonl", results)
        print(f"Executed {len(results)} tests against {args.target}. Wrote output/execution_results.jsonl")

    elif args.command == "evaluate":
        profile = load_system_profile(args.profile)
        runtime_config = load_runtime_config(args.runtime_config)
        if args.llm_judge and runtime_config.judge.mode == "llm":
            require_api_key(runtime_config.judge.llm, "LLM judge")
        records = read_jsonl(args.results)
        evaluated = []
        for record in records:
            test = TestCase.model_validate(record["test_case"])
            target_result = record["target_result"]
            deterministic = deterministic_trace_evaluators(test, target_result, profile)
            judge = llm_judge_stub(test, target_result) if args.llm_judge else None
            aggregate = aggregate_evaluation(test, target_result, deterministic, judge, runtime_config.judge.confidence_threshold)
            aggregate["vulnerability"] = test.vulnerability
            aggregate["attack_strategy"] = test.attack_strategy
            evaluated.append(aggregate)
        write_jsonl(OUTPUT / "evaluated_results.jsonl", evaluated)
        print(f"Evaluated {len(evaluated)} results. Wrote output/evaluated_results.jsonl")

    elif args.command == "regression":
        profile = load_system_profile(args.profile)
        ensure_target_allowed(profile, args.target)
        results = run_async(run_regression_tests(args.tests, mocked_target_callback))
        write_jsonl(OUTPUT / "regression_results.jsonl", results)
        generate_regression_comparison_report(results, OUTPUT / "regression_report.md")
        print("Wrote output/regression_results.jsonl and output/regression_report.md")

    elif args.command == "report":
        results = read_jsonl(args.results)
        generate_markdown_report(results, OUTPUT / "report.md")
        generate_json_report(results, OUTPUT / "report.json")
        print("Wrote output/report.md and output/report.json")


if __name__ == "__main__":
    main()
