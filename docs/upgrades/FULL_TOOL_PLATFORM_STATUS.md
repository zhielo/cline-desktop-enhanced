# Full tool platform upgrade — issue #98

Fresh baseline: `2e4f41342e50d7599b686c7173e8d9eb7859e380` on main. Source branch: `work/full-tool-platform-upgrade`. No prior recovery patch, partial upgrade branch or installer is the baseline.

## Checkpoint 1: actual core source, not a completed release

This checkpoint supplies a working bounded SDK metadata registry, a bounded ordered command-batch executor, production integration instructions and regression tests. A branch-restricted source-writing workflow commits the deterministic bindings to the same upgrade branch before validation; generated-only CI changes never count as delivery.

The registry does not manufacture installed/licensed/healthy/allowed status. It inspects only the constructor-owned builtin registration list before subsequent policy filters, omits dynamic descriptor getters, exposes schema field names rather than default values, pages results, and never grants authority.

Commands run sequentially by default. Only the host can configure 1..4 independent workers. A monotonic end-to-end batch budget covers queue waits. Abort/expiry blocks later launches, forwards cancellation, and labels unverified physical cleanup. Existing executor-specific environment filtering, process management and permission guards are retained. Global multi-agent scheduling and Windows Job Objects are not implemented here.

## Required evidence

Source integration, SDK compilation, preservation, full core regression tests, desktop type checking and the existing sidecar suite must produce real results. Tests in the source are not evidence that they have passed. The source-writing workflow publishes the exact integrated revision for the read-only validation job.

## Not delivered yet

The engineering, native/Android, isolated-runtime, security/evidence and build/operations adapter packs remain open in #98. Native engine lifecycle/database fixes, device/VM verification, UI work, final Windows smoke and the consolidated installer are not complete. Do not advertise an all-tools upgrade or package a baseline-only installer.

Keep the existing unsigned installer/updater policy. Only after the complete consolidated source passes its required gates should a fresh feat/** branch trigger the one final Windows installer. No automatic main merge, release tag or publication.
