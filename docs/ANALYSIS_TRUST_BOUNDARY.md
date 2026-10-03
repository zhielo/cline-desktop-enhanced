# Analysis trust boundary

The desktop Analysis workbench is a host-enforced capability boundary. It does
not make the Windows host a malware sandbox.

## Approval contract

1. The sidecar validates the tool schema and canonicalizes every path.
2. Existing paths resolve through their real filesystem identity. Future output
   paths resolve through the nearest real parent.
3. The complete normalized request is serialized with sorted object keys and
   hashed with SHA-256.
4. The review surface shows that request and hash.
5. Approval produces a single-use token valid for ten minutes.
6. Execution succeeds only when the workspace, task kind, complete request hash,
   token, and target identity still match.

PID, address, engine, debugger, output paths, execution flags, and timeout are
part of the approved request. Changing any field requires a new plan.

## Durable ledger

The ledger lives under the private Cline data directory with restrictive file
permissions. It never stores plaintext execution tokens. Running work found
after restart becomes `interrupted`; pending authorization becomes invalid.
Retention is bounded and stale approvals expire automatically.

## Evidence

Completed tasks record the request hash, canonical result hash, tool identity,
and bounded output paths. Users can export a JSON evidence bundle into
`.cline/analysis-evidence`. The bundle is evidence metadata, not a claim that
an external artifact is harmless.

## Dynamic analysis

The desktop host never executes a dynamic sample. A worker is considered
eligible only when:

- its endpoint uses HTTPS;
- its public key is pinned locally;
- `/v1/capabilities` returns an unexpired Ed25519-signed manifest;
- the manifest declares disposable snapshots and disabled networking support.

Provisioning Hyper-V, Windows Sandbox, or a remote VM remains an external
administrator responsibility. Merely setting an environment variable does not
enable execution.
