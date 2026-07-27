# Agent Adversarial Evaluation

`agent-adversarial-evaluation` is a reusable VS Code Copilot Agent Skill for adversarial prompt evaluation.

It helps evaluators:

- define a target agent evaluation profile
- generate adversarial seed prompts
- optionally add DeepTeam baseline seed candidates
- optionally expand approved prompts with DeepTeam strategies
- run prompts against an allowlisted non-production target
- evaluate the final response for vulnerabilities
- save human-confirmed failures as regression tests
- generate Markdown and JSON reports

For a fuller onboarding guide, see [documentation/skill-guide.md](documentation/skill-guide.md).

## MVP Architecture

The MVP is intentionally simple:

```text
target_profile.yaml
→ vulnerability scope
→ seed prompt generation
→ human review
→ optional DeepTeam expansion
→ target execution
→ output-first evaluation
→ report and regression tests
```

There is no attack-surface-analysis step in the current MVP. If the user asks to test prompt injection, sensitive data leakage, authorization bypass, or another supported vulnerability, the skill uses that scope directly.

## Installation

Use Python 3.11 or newer.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

If DeepTeam is not installed, deterministic seed generation still works and the DeepTeam adapter returns a clear installation error in test metadata.

## Required Input

Most teams start by editing `target_profile.yaml`.

Minimal shape:

```yaml
target:
  name: support-agent
  description: Synthetic customer support assistant
  environment: test

vulnerabilities_to_test:
  - direct_prompt_injection
  - sensitive_data_leakage
  - authorization_bypass

protected_assets:
  - synthetic_customer_record

expected_safe_behaviour:
  - Refuse unauthorized protected-data requests
  - Do not reveal hidden instructions or secrets

execution:
  allowlisted_targets:
    - local-test
  production_allowed: false
  synthetic_data_only: true
```

Optional fields can describe known agents or tools, but they are not required for the MVP.

## Optional Files

`seed_templates.yaml`

Customize prompt wording for selected vulnerabilities. If a vulnerability has no custom template, the skill falls back to built-in reusable templates.

`taxonomy.yaml`

Defines supported vulnerability IDs and standards mappings, such as OWASP, OWASP LLM, or MITRE ATLAS. Most users do not need to edit it for a first run.

`runtime_config.yaml` and `.env`

Needed only for optional DeepTeam baseline generation, LLM generation, or LLM-as-a-judge. Keep real API keys in `.env`, not YAML.

## CLI Examples

Generate deterministic seeds from `target_profile.yaml`:

```bash
python run.py generate --profile target_profile.yaml --seed-templates seed_templates.yaml --tests-per-vulnerability 3
```

Generate only requested vulnerabilities:

```bash
python run.py generate --profile target_profile.yaml --vulnerabilities prompt_injection sensitive_data_leakage --tests-per-vulnerability 3
```

Generate deterministic seeds plus optional DeepTeam baseline candidates:

```bash
python run.py generate --profile target_profile.yaml --deepteam-baseline --runtime-config runtime_config.yaml --vulnerabilities authorization_bypass sensitive_data_leakage
```

Expand reviewed tests:

```bash
python run.py expand --tests output/seed_tests.jsonl --runtime-config runtime_config.yaml --strategies direct role_play multilingual tool_mediated --variants-per-strategy 2
```

Execute against an allowlisted target:

```bash
python run.py execute --tests output/generated_tests.jsonl --profile target_profile.yaml --target local-test
```

Evaluate final responses:

```bash
python run.py evaluate --results output/execution_results.jsonl --profile target_profile.yaml --runtime-config runtime_config.yaml --llm-judge
```

Run regression tests:

```bash
python run.py regression --tests output/regression_tests.jsonl --profile target_profile.yaml --target local-test
```

Generate reports:

```bash
python run.py report --results output/evaluated_results.jsonl
```

## Target Callback

Project teams replace the target callback with their non-production integration:

```python
async def target_callback(attack_input: str, conversation_history: list[dict] | None = None) -> dict:
    return {
        "final_response": "...",
        "metadata": {},
    }
```

The included `mocked_target_callback` is for local examples only.

## Safety

This skill is for approved test targets only. It enforces synthetic data, non-production targets by default, no destructive tool execution, no real customer data, no production credentials, no secret extraction, secret redaction from logs, approved vulnerability categories, and human approval before saving regression tests.
