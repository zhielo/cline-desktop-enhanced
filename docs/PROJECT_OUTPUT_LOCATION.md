# Fixed Windows project output location

Default root: `C:\Cline-Outputs`.

Each selected project path maps to a stable `<sanitized-name>-<16-hex-workspace-hash>` directory, preventing two unrelated appcloner folders from sharing outputs. Windows slash/case spelling is normalized; filesystem aliases and moved workspaces are distinct identities. The folder contains deliverables, reports and logs. The exact path is shown in the local session header.

Copy path only copies the computed project directory. Open outputs explicitly creates the layout with the current Windows account and opens Explorer. Passive navigation/refresh does not create or open anything. Existing junction/link redirects and non-directory entries are rejected. Permission errors stay visible: no silent AppData fallback, elevation or root-policy change. These checks are not an OS sandbox or an atomic defense against privileged concurrent filesystem modification.

New local Windows session prompts supply these absolute destinations for generated files. Keep source edits in the original workspace. Preserve dist/build/out conventions and managed private captures/native databases; do not migrate existing data. Arbitrary shell commands and tool calls with explicit output paths are not intercepted or forcibly redirected. This implementation does not guarantee that every external program follows agent guidance. Existing persisted session prompts are not rewritten mid-task; start a new/rebuilt session to obtain the default.

SSH/cloud output remains on its owning host; non-Windows desktop hosts have no fictional C drive destination. The header button is not available for remote/cloud sessions.

Mandatory validation covers deterministic path identities, invalid paths, no filesystem work during resolution, explicit folder creation, root/child junction rejection, local/remote RPC boundaries, permission errors, and stale project UI responses. Windows installer and a manual Explorer/open/preview check remain separate operational validation.

## Windows canonical spelling correction

Build #174 failed the valid folder-creation regression because native canonical spelling differed from the requested path. The reader now verifies non-link directory and parent filesystem identities using bigint device/inode values rather than assuming identical spelling. A new regression failed on the old guard and accepts an alternate spelling only for the same objects; a fake canonical destination with a different identity still fails. Root/child junction tests remain enabled. This is not an atomic host-filesystem lock.
