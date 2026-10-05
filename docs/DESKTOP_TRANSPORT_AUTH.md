# Desktop command-channel authentication

## Boundary

The sidecar's per-process capability now authenticates **all WebSocket commands**, not only interactive tool approvals. Trusted Origin alone is not authentication. Originless integrations are no longer automatically trusted: they must present the capability too. An untrusted browser Origin is rejected even with valid credentials.

The existing `approval_token` WebSocket query is retained for Tauri's private ready-line handoff and development compatibility. A single `Authorization: Bearer ...` header is also accepted for non-browser WebSocket integrations. Duplicate query keys, empty configuration, conflicting header/query sources, malformed bearer credentials and tokens over 512 UTF-8 bytes fail closed. Equality uses constant-time comparison when lengths match.

Connection authentication does not replace tool approval or provider sign-in. Originless authenticated clients retain privileged desktop command access but cannot resolve interactive tool-prompt approvals. This is not a granular third-party integration permission system; do not distribute the capability to untrusted plugins or processes. This change is independent of ClinePass/provider OAuth and does not bypass account errors.

## HTTP endpoints

- `POST /shutdown` and `POST /telemetry/error` require bearer authentication and the existing allowed-Origin policy. HTTP query tokens are not accepted.
- Telemetry bodies are read with a 64 KiB limit independently of declared Content-Length. Diagnostics redact known process capabilities and recognizable bearer/query credentials before field limits/capture. This is not a universal secret scanner.
- Health and marketplace catalog stay public; they never return the capability. Native quitting still signals/terminates the tracked child. No native lifecycle change is required.

## Compatibility

Packaged Tauri startup reads the private sidecar ready-line WebSocket endpoint, including its capability, and does not forward that ready line into ordinary native logs. The existing `dev:headless` command generates an ephemeral token and passes it to both processes. Both flows remain unchanged.

Manually running sidecar and web as unrelated processes without a shared token no longer permits commands. Prefer `bun run dev:headless`. If manual setup is necessary, provide a fresh sidecar capability through `CLINE_SIDECAR_APPROVAL_TOKEN` and an exact `NEXT_PUBLIC_SIDECAR_WS_ENDPOINT` carrying that same capability to the development UI. Do not paste actual capability values into tickets, logs, URLs sent to other people, or committed environment files. The token is a process credential, not a Cline account password. Automatically generated tokens rotate on each process start. If you explicitly override the token, you must rotate that value yourself; a reused override does not gain automatic stale-token revocation.

Keep the sidecar loopback-bound. Existing remote bind configuration is not a secure public deployment: bearer authentication over plain HTTP/WS does not provide transport encryption. No TLS, OS isolation or protection from malicious same-user code/memory access is claimed. Exposing the sidecar externally requires a separate deployment/security design, not disabling this check.

## Validation

Required tests cover missing/wrong/duplicate/conflicting credentials, trusted-origin spoofing, authenticated originless access, no unauthorized dispatch/event replay, stale connections, protected HTTP endpoints, body limits, token redaction and authenticated telemetry delivery. Compiled/installed smoke additionally requires an authenticated diagnostic request, tokenless denials and rejection of the old capability after process restart. All existing recovery, engine, terminal and NSIS/installed-app checks remain blocking. A build success is not a comprehensive security audit.
