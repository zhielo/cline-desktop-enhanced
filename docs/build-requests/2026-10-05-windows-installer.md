# Windows installer build request — 2026-10-05

Run the existing Build custom Windows installer workflow on this dedicated feature branch.

Source baseline: 2e4f41342e50d7599b686c7173e8d9eb7859e380.

This is a rebuild of the committed desktop application. It does not include the unpushed reverse-engineering upgrade draft or change application behavior.

Keep all existing validation, NSIS packaging, installed-binary smoke tests, checksums, and provenance steps enabled. Do not merge this branch or create a release tag as part of this build request.
