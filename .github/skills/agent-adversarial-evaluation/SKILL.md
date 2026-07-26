---
name: agent-adversarial-evaluation
description: Generate, execute, evaluate, and maintain adversarial tests for agent and multi-agent systems using DeepTeam only.
---

# Agent Adversarial Evaluation

Use this skill when the user asks to:

- Generate adversarial tests for this agent system
- Create red-team test cases from scratch
- Analyze agent prompts for security weaknesses
- Test authorization bypass
- Test router or orchestration behavior
- Test unauthorized tool usage
- Execute DeepTeam attacks
- Evaluate agent traces
- Build regression tests from security failures
- Generate a red-team evaluation report

## Workflow

1. Load the system profile.
2. Identify protected assets and critical controls.
3. Identify relevant attack surfaces.
4. Generate original seed test cases.
5. Review and validate generated seeds.
6. Expand approved seeds using DeepTeam.
7. Execute attacks only against an allowlisted test target.
8. Capture the final response and execution trace.
9. Run output-first deterministic evaluators.
10. Run the optional LLM judge for subjective checks.
11. Identify the likely failed component.
12. Save human-confirmed failures as regression tests.
13. Generate Markdown and JSON reports.

## Operating Rules

- Use DeepTeam as the only red-teaming framework.
- Load `runtime_config.yaml` and `.env` when optional LLM attack generation or LLM-as-a-judge is requested.
- Keep API keys in `.env`; never place real secrets in YAML, reports, JSONL, prompts, or traces.
- Support deterministic generation by default, with optional LLM or hybrid generation through an approved callback.
- Support optional DeepTeam baseline seed candidates as an additive source; validate and review them before execution.
- Generate initial tests from the configured agent descriptions, prompts, routing flow, tool permissions, authorization rules, guardrails, protected data, required workflow order, expected safe behaviour, and prohibited behaviour.
- Do not require existing test cases.
- Execute attacks only against allowlisted non-production targets.
- Use synthetic accounts and records only.
- Do not execute destructive tools.
- Do not use real customer data, production credentials, or secret extraction.
- Redact secrets from logs and reports.
- Use the default vulnerability catalog from `taxonomy.yaml`; customize it only when the project needs different categories or OWASP/MITRE mappings.
- Require human review for newly identified attack categories, generated seed tests before first execution, critical attack categories, low-confidence LLM judge results, saving failures as regression tests, and newly added targets.
- Do not claim that this skill replaces security reviewers.

## Reuse Points

Other teams should normally update only:

- `system_profile.yaml`
- `taxonomy.yaml` when custom categories or standards mappings are needed
- `seed_templates.yaml` when domain-specific seed wording is needed
- the target callback
- trace-field mapping
- project-specific deterministic rules

Keep the main generation, DeepTeam integration, validation, regression handling, and reporting logic reusable.
