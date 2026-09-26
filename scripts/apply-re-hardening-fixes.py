from pathlib import Path


def replace_once(path: str, old: str, new: str) -> None:
    p = Path(path)
    source = p.read_text()
    if source.count(old) != 1:
        raise RuntimeError(f"{path}: expected one occurrence, found {source.count(old)}")
    p.write_text(source.replace(old, new, 1))

replace_once(
    "sdk/packages/core/src/extensions/tools/executors/reverse-engineering.ts",
    '''async function toolVersion(engine: Engine, command: string | undefined): Promise<string | undefined> {
\treturn (await toolIdentity(engine, command)).version;
}
''',
    "",
)
replace_once(
    "sdk/packages/core/src/extensions/tools/model-tool-routing.ts",
    '''\t\t| "enableReverseEngineering"
\t\t| "enableAndroidDevice"''',
    '''\t\t| "enableReverseEngineering"
\t\t| "enableLiveDebugger"
\t\t| "enableAndroidDevice"''',
)
replace_once(
    "sdk/packages/core/src/extensions/tools/model-tool-routing.ts",
    '''\treverse_engineer: "enableReverseEngineering",
\tandroid_device: "enableAndroidDevice",''',
    '''\treverse_engineer: "enableReverseEngineering",
\tlive_debugger: "enableLiveDebugger",
\tandroid_device: "enableAndroidDevice",''',
)
print("Applied follow-up routing fixes")
