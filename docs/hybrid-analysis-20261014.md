# Hybrid analysis workflow

## Scope and use

Hybrid is an optional, session-specific fourth mode beside Off, Static and Runtime. Existing modes and the default Off selection are unchanged; no existing session is migrated. Select Hybrid while the local session is idle. Mode selection itself performs no static inspection, launch, attachment or recording.

The workflow is **inspect statically → name an unresolved question → select the owning static evidence → prepare/review → explicitly approve → observe → reconcile selected evidence**. It is evidence-guided orchestration of the existing supported tools, not automatic execution of every target. Available model tools can perform native static analysis and propose built-in-browser recording; this patch does not expose arbitrary target execution to the model.

## Static basis and immutable runtime plans

Hybrid proposals contain only a completed parser receipt or native static-task ID and a bounded question. These selections are not consent or authority. The host requires the exact owning session/workspace and verifies evidence hashes. A binary handle without completed inspection is insufficient.

For supported first-party Inspector, native-module observation and isolated standalone JavaScript execution, Hybrid additionally requires a matching current target SHA-256 in the selected static evidence. Targets are confined to the owning workspace in Hybrid. The host-derived basis hash and question are part of the immutable runtime request and approval hash. Admission rechecks the basis and current target before consuming the existing one-use token. Changed evidence, target, workspace or mode denies work; no automatic retry or fallback occurs.

The workspace UI accepts a selected parser receipt or a completed native static task ID and an unresolved question. Changes invalidate pending UI reviews. Runtime mode retains its previous behavior and prerequisites; Hybrid does not weaken Debug, sensitive-memory or Execute approval, process-birth checks, resource verification, kernel isolation, cancellation, timeout or cleanup requirements.

## Browser scenarios and shared evidence

Hybrid browser start validates a static receipt/task basis before model-requested human recording consent. The backend checks it again before starting capture. Browser metadata is associated with an investigation, not cryptographically proven to come from the selected binary; its relation is explicitly `investigation-context-only`. No navigation, target launch or action replay is added.

The original host-derived basis/question remains attached to a recording even if its stop request supplies different text. Existing recording can still be stopped after switching to Off. Runtime task snapshots retain approved Hybrid context. Selected trace/export records show the pairing, question and unresolved status, without upgrading labels, timing or byte equality into causal proof. Select both the static record and runtime record when exporting their shared evidence bundle. Existing export budgets/redaction remain.

No new corroboration verdict is fabricated: Hybrid question resolution and causality remain unresolved unless established by an existing explicit, scoped verifier. Full Android/APK observation still requires the existing device/worker configuration; Hybrid does not turn every native sample into an executable supported scenario.

## Validation and limitations

Regression tests cover mode persistence and default preservation; strict proposal schemas; missing, altered and cross-session evidence; static-task integrity; changed target hashes; fresh recording consent; denial without capture; cleanup after mode changes; original recording-basis retention; and report claims. Installed WebView acceptance additionally selects Hybrid, reloads it, verifies preserved static receipts, exercises static-only preflight and denies missing evidence before returning Off. It also explicitly prepares/approves an owned standalone fixture, asserts kernel-verified isolated execution and host-observed exit/stdout predicates, and exports its selected static/runtime evidence. This is a deterministic owned fixture, not arbitrary target or live-model acceptance.

These tests do not establish live-model acceptance, licensed IDA availability, general indirect-call recovery, runtime relocation completeness, complete Electron/.NET semantics or superiority over REA. Fresh PR Windows SDK, installer, isolation and installed-WebView checks remain required before merge.

Before downgrading to an older app that does not recognize Hybrid, switch affected sessions back to Off/Static/Runtime while idle; this patch does not modify older binaries' schemas.
