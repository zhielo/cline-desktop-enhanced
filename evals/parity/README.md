# Objective Codex-parity benchmark

This benchmark replaces impression-based percentages with a versioned task
corpus and comparable run results.

Each scenario result records only:

- a score from `0` to `1`;
- duration in milliseconds;
- human-intervention count;
- optional aggregate token and reported cost units.

It stores no prompts, model output, repository paths, environment variables,
screenshots, typed text, or user identity.

## Usage

```bash
bun evals/parity/codex-parity.ts \
  --corpus evals/parity/corpus.v1.json \
  --candidate candidate-run.json \
  --reference codex-reference-run.json \
  --output parity-report.json
```

Without `--reference`, the report provides candidate readiness and corpus
coverage but deliberately omits a Codex-relative percentage. A parity
percentage is valid only when both products run the same corpus version in a
documented comparable environment.

Scenario runners should use deterministic fixtures and product-observable
success criteria. Feature presence, marketing claims, or manually estimated
weights do not count as task completion.