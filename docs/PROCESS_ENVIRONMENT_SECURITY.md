# Process environment and secret protection

Cline Enhanced applies a host-enforced environment policy to SDK `run_commands` processes and resumable `ProcessSessionManager` processes. The model cannot bypass this policy by adding a sensitive key to an `env` override.

## Default behavior

- Non-sensitive host variables remain available for developer-tool compatibility.
- Credential-bearing names such as `*_TOKEN`, `*_API_KEY`, `*_SECRET`, passwords, private keys, authorization values, cloud credentials, and credential-bearing URLs are withheld.
- Matching is case-insensitive for Windows compatibility.
- Safe overrides remain available; sensitive overrides are filtered by the same policy as inherited values.
- The host can disable environment inheritance entirely.

Variables are classified by both name and value. For example, an `HTTPS_PROXY` value containing embedded username/password credentials is sensitive even though the variable name does not contain `TOKEN` or `SECRET`.

## Explicit grants

A host integration can grant an exact sensitive variable name through `allowedSensitiveEnvironmentVariables`. This is an execution-policy decision, not a model-controlled argument.

Granted credentials:

- are available only to executors configured with that grant;
- remain redacted from stdout, stderr, final tool results, failures, retained process output, and detached-command logs;
- are not written into task state or telemetry by this policy.

Use integrations or credential helpers instead of environment injection when possible. A GitHub operation should normally use the authenticated GitHub integration or `gh` credential storage rather than copying a token into every child process.

## Output redaction

Output is sanitized before it enters the command collector or process-session buffer. Redaction covers:

- exact known environment-secret values, including values split across output chunks;
- API-key, token, password, authorization, secret, credential, and private-key assignments;
- Bearer and Proxy-Authorization values;
- credentials embedded in URLs;
- common GitHub, AWS access-key, and `sk-` token forms;
- PEM private-key blocks.

The same sanitized stream feeds UI progress, final command output, errors, detached logs, and resumable-session reads. Raw command output is not retained alongside the sanitized version.

## Security boundary

Filtering and redaction reduce accidental disclosure. They do not make an untrusted command safe:

- A process may read credentials from files, OS credential stores, named pipes, agents, or network services.
- An allowed credential can still be transmitted over the network by the process using it.
- Pattern redaction cannot recognize every unknown secret format.

Filesystem, network, MCP, and operating-system sandbox controls remain required. “Full access” may grant a credential to an approved operation, but it must not disable output redaction.

## Validation

Tests cover classification, case-insensitive grants, inherited and override filtering, credential-bearing URLs, assignment and token redaction, chunk-boundary redaction, `run_commands`, and process-session output.

This policy does not change the unsigned, artifact-only Windows installer workflow and does not publish a GitHub Release.