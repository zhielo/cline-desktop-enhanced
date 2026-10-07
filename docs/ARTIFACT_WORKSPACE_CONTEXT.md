# Transcript artifact workspace context fix

## Confirmed failure

On PR #103's initial commit `5810d60f8ce864bbcf673468ff3fe2b0549da72f`, the page supplied the selected session's workspace to `ChatMessages`, but nested Markdown file links did not forward either `cwd` or `environmentId` to artifact commands. The backend therefore used its local startup workspace and active environment. A relative `out/REPORT.md` could incorrectly resolve under the installed app's AppData folder rather than the project. Clipboard-only Copy path did not require resolution, explaining why it still worked.

Six new transcript interaction regressions failed before the fix: left-click Markdown preview, the three right-click actions, originating SSH environment, and workspace changes with unchanged memoized content.

## Fix and preserved behavior

`ArtifactWorkspaceProvider` scopes `cwd` and `environmentId` to each transcript and memoizes the value. Markdown editor/system opening reads this context; artifact menus inherit it unless a caller supplies an explicit workspace/environment. This covers assistant messages, reasoning and tool-output Markdown without prop-drilling or a mutable global workspace. Preview/open/reveal share the same scope. Existing completion-card and workspace-file explicit bindings remain supported. A session or environment switch updates context even when the Markdown content itself is memoized.

- Markdown/text preview stays in-app and never navigates to `__cline_file__`.
- External URL safety, remote-image privacy and clipboard behavior are unchanged.
- SSH artifacts remain blocked by the backend; they are not opened using the local desktop's active environment.
- No recursive disk search, path guessing, sample execution or automatic archive extraction is added.

## Important distinction for the reported screenshot

`xl/worksheets/sheet1.xml` is commonly an entry *inside* an XLSX ZIP container. Unless extracted into the workspace, it is not a standalone file. The workspace handoff fix does not claim that archive-member labels, nonexistent/generated-but-unsaved files, or files on a remote machine become locally openable. Open the actual XLSX container or deliberately extract an authorized copy when the member itself is needed. Similarly, APK or binary system opening requires an installed Windows file association; metadata-only preview is intentional for unsupported binary types. The existing 2 MiB preview limit remains in force.

## Validation boundary

Interaction tests cover all three artifact menu RPCs and Markdown preview with an explicit project directory, originating SSH environment, and a context change while text remains unchanged. Backend tests read a real fixture Markdown file relative to the supplied project directory, keep all three SSH actions blocked, and reject a nonexistent archive-member path rather than pretending it exists. Exact-head Windows installer and regression CI must be rerun; a previously successful PR #103 installer does not contain this new source change.


Local validation on the patched source passed: desktop typecheck, 182 chat UI tests, 1,324 sidecar/UI tests in the sidecar suite, changed-file lint (zero errors), source-preservation verification, and the production Next.js webview build. Test-suite counts overlap and are not a total of unique tests. These Linux checks do not prove native Windows file associations or real Explorer launches; the updated installer and Windows regression workflow remain separate gates.
