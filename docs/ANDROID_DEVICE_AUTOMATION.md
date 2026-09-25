# Android device automation

`android_device` supports attached, already-authorized devices. It selects the only ready device automatically and requires `device_serial` when several are attached.

## Observe and act

Use `screen_info`, `screenshot`, and `ui_hierarchy` to inspect the device. Use coordinate-validated `tap`, `long_press`, and `swipe`, allowlisted `key_event`, or redacted `text_input` to interact. `require_foreground_package` can guard actions. Absolute `before_screenshot_path` and `after_screenshot_path` values capture private PNG evidence and report a SHA-256-based `screenChanged` result. Delete sensitive evidence when no longer needed.

## Unrestricted shell

`operation: "shell"` requires non-empty `shell_args` and `acknowledge_risk: true` on every call. Arguments are passed after `adb shell`; use `["sh", "-c", "..."]` for shell syntax. This is unrestricted within the Android shell user's permissions and can expose, modify, or delete accessible data. Arguments are redacted from returned command metadata, but stdout/stderr may be sensitive. Timeouts, cancellation, bounded output, authorization checks, and explicit multi-device selection remain enforced. The tool does not enable root or bypass Android security.
