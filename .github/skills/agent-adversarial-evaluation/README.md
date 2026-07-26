# Agent Adversarial Evaluation

`agent-adversarial-evaluation` is a reusable VS Code Copilot Agent Skill for generating, expanding, executing, evaluating, and maintaining adversarial tests for agent and multi-agent systems.

For a fuller onboarding guide, see [documentation/skill-guide.md](documentation/skill-guide.md).

DeepTeam provides adversarial attack generation and execution.

This skill adds:

- application-specific system understanding
- business-rule-based seed generation
- agent-routing evaluation
- authorization validation
- tool-usage validation
- trace-level root-cause analysis
- regression-test management
- stakeholder reporting

## Why DeepTeam

DeepTeam is the only red-teaming framework used here. It supplies attack enhancement strategies such as role-play, authority claims, multilingual prompts, obfuscation, prompt injection, indirect prompt injection, tool-mediated attacks, and multi-turn attacks where supported. The skill keeps DeepTeam-specific objects behind a small adapter so teams work with stable `TestCase` and evaluation schemas.

## Installation

Use Python 3.11 or newer.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

If DeepTeam is not installed, deterministic seed generation still works and the DeepTeam adapter returns a clear installation error in test metadata.

## Runtime Config And API Keys

Use `runtime_config.yaml` to choose deterministic, LLM, or hybrid attack generation and to configure the optional LLM-as-a-judge.

Secrets do not go in YAML. Copy `.env.example` to `.env` and add approved non-production API keys there:

```bash
cp .env.example .env
```

```text
OPENAI_API_KEY=...
OPENAI_BASE_URL=...
```

`runtime_config.yaml` controls which environment variable is read:

```yaml
generation:
  mode: deterministic
  allow_deterministic_fallback: true
  llm:
    provider: openai
    model: gpt-4.1-mini
    api_key_env: OPENAI_API_KEY

judge:
  mode: disabled
  confidence_threshold: 0.75
  llm:
    provider: openai
    model: gpt-4.1-mini
    api_key_env: OPENAI_API_KEY
```

Generation modes:

- `deterministic`: local templates and configured DeepTeam strategies only
- `llm`: require an API key and approved LLM generator callback
- `hybrid`: use the LLM callback when available, otherwise fall back to deterministic generation if allowed

The skill does not print raw API keys and redacts secret-like values from JSONL output.

## Folder Structure

```text
.github/
└── skills/
    └── agent-adversarial-evaluation/
        ├── SKILL.md
        ├── README.md
        ├── requirements.txt
        ├── runtime_config.yaml
        ├── .env.example
        ├── seed_templates.yaml
        ├── system_profile.yaml
        ├── taxonomy.yaml
        ├── skill.py
        ├── evaluator.py
        ├── reporter.py
        ├── run.py
        ├── example_profile.yaml
        ├── test_skill.py
        └── documentation/
            └── skill-guide.md
```

## System Profile

Most teams start by editing `system_profile.yaml`. Describe the system, agents, tools, protected assets, required workflow order, guardrails, prohibited behaviours, supported languages, and allowlisted targets. For better reuse across different architectures, agents may also declare semantic `roles` such as `verifier`, `classifier`, `router`, `restricted_executor`, `retriever`, or `guardrail`; the skill infers reasonable defaults when roles are omitted.

The loader validates agent names, tool definitions, allowed agents, required flow entries, protected assets, allowlisted environments, production restrictions, and destructive tools.

## Attack Surfaces

Attack surfaces are identified from configuration rules:

- authorization-protected tools create authorization bypass, cross-subject access, and argument manipulation surfaces
- routers or orchestrators create router override, intent manipulation, and invalid component-selection surfaces
- RAG or document-consuming agents create indirect prompt injection surfaces
- textual tool outputs create tool output injection surfaces
- protected assets create sensitive data leakage surfaces

## Seed Generation

The skill generates original tests from scratch. It does not require existing test cases. Seed tests include a clear objective, expected safe behaviour, measurable failure conditions, target component, severity, and synthetic test data only.

The initial MVP supports authorization bypass, cross-subject access, intent manipulation, router override, unauthorized tool usage, tool-argument manipulation, direct prompt injection, indirect prompt injection, tool-output injection, and sensitive-data leakage.

Seed generation uses deterministic control-pattern templates by default. Teams may optionally edit `seed_templates.yaml` to customize domain wording while keeping the same required fields and validation. If a vulnerability is missing from `seed_templates.yaml`, the skill falls back to a built-in reusable archetype.

Teams can also add optional DeepTeam baseline seed candidates with `--deepteam-baseline`. These candidates are generated from the target purpose, selected vulnerabilities, and DeepTeam's simulator, then normalized into the same internal `TestCase` schema. They are additive discovery candidates, not a replacement for deterministic business-rule seeds.

## DeepTeam Expansion

`DeepTeamRunner.expand_tests` expands approved seeds with configured strategies. It can run with deterministic generation, or with an approved LLM generator callback configured through `runtime_config.yaml` and `.env`.

- direct
- role_play
- authority_claim
- multilingual
- obfuscated
- tool_mediated

DeepTeam results are normalized back into the internal `TestCase` schema.

## Target Callback

Project teams replace only the callback:

```python
async def target_callback(attack_input: str, conversation_history: list[dict] | None = None) -> dict:
    return {
        "final_response": "...",
        "trace": [],  # optional; include spans only when available
        "metadata": {},
    }
```

The included `mocked_target_callback` is for local examples only. Do not use it as a production integration.

## Evaluation

Evaluation is output-first. The basic path checks the final response for unsafe compliance, protected data leakage, system-prompt disclosure, and incomplete refusal behavior. If a target also returns trace spans, optional trace evaluators check authorization order, routing, tool usage, and guardrails. A critical trace failure is never overridden by a safe-looking final response.

The optional LLM judge is only for subjective response-quality checks such as partial leakage, incomplete refusal, indirect assistance, fake authority acceptance, misleading but technically compliant answers, and indirect achievement of the attack objective. It is not used to decide factual trace events when trace data exists.

## Regression Tests

Human-confirmed failures can be saved as JSONL regression records. Low-confidence LLM-judge failures are not saved automatically. Regression execution classifies outcomes as Fixed, Still failing, Newly changed, or Requires review.

## Reports

Reports are generated as Markdown and JSON. They summarize surfaces, seed tests, DeepTeam variants, accepted and rejected tests, duplicate removals, execution results, failures by vulnerability, strategy, agent and tool, critical findings, guardrail false positives and false negatives, human review needs, and regression status.

## Safety

This skill is for approved test targets only. It enforces synthetic accounts and records, non-production targets by default, no destructive tool execution, no real customer data, no production credentials, no secret extraction, secret redaction from logs, approved vulnerability categories, and human approval for new target environments.

Human review is required for newly identified attack categories, generated seed tests before first execution, critical attack categories, low-confidence LLM-judge results, saving failures as regression tests, and testing newly added targets. This skill supports security reviewers; it does not replace them.

## Reuse

Other teams should normally modify only:

- `system_profile.yaml`
- `taxonomy.yaml` when custom categories or standards mappings are needed
- `seed_templates.yaml` when domain-specific wording is needed
- target callback
- trace-field mapping
- project-specific deterministic rules

The main generation, DeepTeam integration, validation, regression handling, and reporting logic should remain reusable.

## CLI Examples

```bash
python run.py analyze --profile system_profile.yaml
```

```bash
python run.py generate --profile system_profile.yaml --seed-templates seed_templates.yaml --vulnerabilities authorization_bypass router_override direct_prompt_injection unauthorized_tool_call --tests-per-vulnerability 5
```

```bash
python run.py generate --profile system_profile.yaml --seed-templates seed_templates.yaml --deepteam-baseline --runtime-config runtime_config.yaml --vulnerabilities authorization_bypass router_override unauthorized_tool_call --tests-per-vulnerability 3
```

```bash
python run.py expand --tests output/seed_tests.jsonl --runtime-config runtime_config.yaml --strategies direct role_play multilingual tool_mediated --variants-per-strategy 2
```

```bash
python run.py execute --tests output/generated_tests.jsonl --profile system_profile.yaml --target local-test
```

```bash
python run.py evaluate --results output/execution_results.jsonl --profile system_profile.yaml --runtime-config runtime_config.yaml --llm-judge
```

```bash
python run.py regression --tests output/regression_tests.jsonl --profile system_profile.yaml --target local-test
```

```bash
python run.py report --results output/evaluated_results.jsonl
```

## Example Copilot Prompts

```text
Use the agent-adversarial-evaluation skill.

Analyze the configured agent system and identify relevant attack surfaces.

Generate five original test cases for:

- authorization bypass
- router override
- prompt injection
- unauthorized tool usage

Expand approved tests using DeepTeam with:

- direct
- role-play
- multilingual
- tool-mediated strategies

Validate and deduplicate the generated tests.

Execute them only against the configured test target.

Evaluate the final response and optional execution trace.

Create deterministic checks for response safety, authorization, routing, tool usage, and guardrail behaviour.

Save human-confirmed failures as regression tests and generate a Markdown report.
```
