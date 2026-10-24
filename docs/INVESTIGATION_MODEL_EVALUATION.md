# Investigation model evaluation

This opt-in source-host harness uses the production Agent, provider transport,
reviewed host investigation tools, real parser child and owning-session saved
receipts. It does not change app startup, shell policy or licensing checks.

## What is checked

Two newly generated synthetic artifacts exercise:

1. Open one owned JavaScript bundle, recover its literal factory, read saved
   evidence and report the exact factory count and source hash.
2. Open one owned PyInstaller CArchive, read metadata, read saved evidence and
   report its randomized declared entry name, Python version and input hash.

The scorer requires strict JSON, actual host review/execution, a receipt really
read in the same session, exact source identity and the known answer. Invented
receipts, missing evidence, wrong counts, extra fields, Markdown and claims of
execution, verified behavior, complete source recovery or decoded payloads fail.
A completed Agent run is also required. No LLM judges its own answer.

The verified bundled `investigate-artifact` skill is included in the system
prompt. Reviews are programmatic **owned-fixture test authority**, not a human
consent test. Only the two scenario tools and a saved-evidence reader are
exposed; no shell, publication, arbitrary input, runtime capture or native tools.

## Credential-free preflight

After the usual frozen dependency install and SDK build, on Linux:

```sh
node scripts/test-investigation-model-transport.mjs
```

This starts a bounded loopback OpenAI-compatible streaming fixture. It checks
8 HTTP requests and two complete three-tool journeys, deriving responses from
actual retained evidence (no known-answer fallback). It never contacts a model.
Reports say `scripted-transport-preflight-production-agent-and-host-tools` and
`liveModel: false`. Temporary reports are removed after assertions. This test is
also run by the Linux general-recovery validation job.

## Actual provider evaluation

Explicitly configure these environment variables in a trusted local environment:

- `CLINE_LIVE_INVESTIGATION_EVAL=1`
- `CLINE_INVESTIGATION_EVAL_MODE=live` (default)
- `CLINE_INVESTIGATION_EVAL_PROVIDER`: configured supported provider ID
- `CLINE_INVESTIGATION_EVAL_MODEL`: exact model ID
- `CLINE_INVESTIGATION_EVAL_API_KEY`: required credential for that provider,
  supplied through a secure environment mechanism, not committed or put in chat
- `CLINE_INVESTIGATION_EVAL_BASE_URL`: optional provider endpoint; HTTPS or
  explicit loopback HTTP only, without URL credentials, query or fragment
- `CLINE_INVESTIGATION_EVAL_REPORT`: new absolute `.json` output path

Then run from `apps/examples/desktop-app`:

```sh
bunx vitest run sidecar/investigation-model.live.test.ts --config vitest.config.mts
```

The real provider receives synthetic source/evidence and the bundled skill;
usage may incur charges. No production provider configuration is loaded. Each
scenario has a 180-second wall budget, 10 Agent iterations and 12 tool calls.
Missing configuration is an error when opted in, not a pass. Normal test runs
explicitly skip the live suite. Only an actual provider run can supply model
quality evidence; scripted preflight success cannot substitute for it.

The new exclusive report contains commit/dirty state, skill hash, provider/model,
run status, duration, tool names, receipt IDs, usage and exact-score checks. It
omits credentials, endpoint URLs, transcripts, raw provider errors and source
text. Treat usage as provider-reported; it is not independent billing evidence.
A failed provider journey records failure rather than replaying automatically.

## Explicit scope limits

Currently Linux source-host only, using isolated temporary app data. This is not
installed Windows validation, human approval UX validation, IDA/Ghidra testing,
Wakaru public recovery testing, adversarial robustness certification, a general
benchmark, all-six-workstream completion or a REA parity claim. Native databases
and broader investigation journeys need separate known-answer cases. A zero
failure result for two fixtures never means the app has no possible problems.
