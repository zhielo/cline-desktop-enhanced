#!/usr/bin/env python3
import os
import re
import subprocess
from pathlib import Path
root = Path(__file__).resolve().parents[1]
branch = os.environ.get("GITHUB_REF_NAME") or subprocess.check_output(["git", "branch", "--show-current"], cwd=root, text=True).strip()
if branch != "work/full-tool-platform-upgrade": raise SystemExit("Wrong source branch")
changes = {}
def read(path): return changes.get(path, (root / path).read_text())
def replace(path, old, new):
    text = read(path)
    if text.count(new) == 1: return
    if text.count(old) != 1: raise SystemExit(f"Ambiguous binary metadata registration: {path}")
    changes[path] = text.replace(old, new, 1)
base = "sdk/packages/core/src/extensions/tools/"
replace(base + "types.ts", '\t| "address_translate"', '\t| "address_translate"\n\t| "binary_metadata"')
replace(base + "types.ts", '\tenableAddressTranslate?: boolean;', '\tenableAddressTranslate?: boolean;\n\t/** Read bounded binary headers within the host-selected workspace. */\n\tenableBinaryMetadata?: boolean;')
replace(base + "constants.ts", '\tADDRESS_TRANSLATE: "address_translate",', '\tBINARY_METADATA: "binary_metadata",\n\tADDRESS_TRANSLATE: "address_translate",')
replace(base + "constants.ts", '\tDefaultToolNames.ADDRESS_TRANSLATE,', '\tDefaultToolNames.BINARY_METADATA,\n\tDefaultToolNames.ADDRESS_TRANSLATE,')
replace(base + "permission-profile.ts", '\t"address_translate",', '\t"address_translate",\n\t"binary_metadata",')
replace(base + "definitions.ts", 'import { createAddressTranslateTool } from "./address-translate";', 'import { createBinaryMetadataTool } from "./binary-metadata";\nimport { createAddressTranslateTool } from "./address-translate";')
replace(base + "definitions.ts", '\t\tenableAddressTranslate = false,', '\t\tenableBinaryMetadata = false,\n\t\tenableAddressTranslate = false,')
replace(base + "definitions.ts", '\tif (enableAddressTranslate) tools.push(createAddressTranslateTool());', '\tif (enableBinaryMetadata) tools.push(createBinaryMetadataTool(config.cwd ?? process.cwd()));\n\tif (enableAddressTranslate) tools.push(createAddressTranslateTool());')
for path in [base + "index.ts", "sdk/packages/core/src/index.ts"]:
    line = 'export { createBinaryMetadataTool, parseBinaryHeaders } from "' + ('./binary-metadata' if path == base + 'index.ts' else './extensions/tools/binary-metadata') + '";'
    if line not in read(path): changes[path] = read(path) + '\n' + line + '\n'
path = base + "presets.ts"
text = read(path)
if 'enableBinaryMetadata:' not in text:
    text, count = re.subn(r'(?m)^(\t\t)enableAddressTranslate: true,', r'\1enableBinaryMetadata: true,\n\1enableAddressTranslate: true,', text)
    if count < 3: raise SystemExit("Missing expected tool presets")
    changes[path] = text
for path in [base + "runtime.ts", base + "model-tool-routing.ts"]:
    text = read(path)
    if '| "enableBinaryMetadata"' not in text:
        text = text.replace('| "enableAddressTranslate"', '| "enableBinaryMetadata"\n\t\t| "enableAddressTranslate"')
        changes[path] = text
    replace(path, '\taddress_translate: "enableAddressTranslate",', '\tbinary_metadata: "enableBinaryMetadata",\n\taddress_translate: "enableAddressTranslate",')
path = base + "runtime.ts"
entry = '\t{ id: "binary_metadata", description: "Bounded non-executing ELF, PE and thin Mach-O header/segment inspection inside the selected workspace.", headlessToolNames: ["binary_metadata"] },\n'
if entry not in read(path): replace(path, '\t{\n\t\tid: "web_search",', entry + '\t{\n\t\tid: "web_search",')
replace(base + "presets.test.ts", '"skills", "address_translate", "tool_registry"', '"skills", "binary_metadata", "address_translate", "tool_registry"')
replace('sdk/packages/core/src/runtime/orchestration/runtime-parity.test.ts', 'expected.splice(spawnIndex, 0, "address_translate", "tool_registry");', 'expected.splice(spawnIndex, 0, "binary_metadata", "address_translate", "tool_registry");')
replace('sdk/packages/core/src/runtime/orchestration/runtime-parity.test.ts', '["address_translate", "tool_registry"].includes', '["binary_metadata", "address_translate", "tool_registry"].includes')
path = 'scripts/verify-custom-fork.ts'
contract = '\t{ path: "sdk/packages/core/src/extensions/tools/binary-metadata.ts", markers: ["createBinaryMetadataTool", "MAX_FILE_BYTES", "targetExecuted: false", "runtimeAddressesObserved: false"] },\n'
if contract not in read(path):
    anchor = '\t{ path: "sdk/packages/core/src/extensions/tools/address-translate.ts", markers: ["createAddressTranslateTool", "user_supplied_segments", "zero_filled", "MAX_ADDRESS"] },\n'
    replace(path, anchor, anchor + contract)
path = 'CUSTOMIZATIONS.md'
section = '\n### Bounded binary header metadata\n\n- `binary_metadata` reads only regular files up to 32 MiB inside the host-selected canonical workspace. It rejects absolute paths, escaped symlinks, changing identities and unsupported variants, uses bounded reads, closes handles, and never executes the target or invokes an external engine.\n- Actual parsers cover ELF32/64 and thin Mach-O32/64 in either byte order, plus PE32/PE32+. SHA256 receipts and declared load/section segments use string-encoded 64-bit addresses.\n- Coverage is explicitly limited to headers and declared segments. Imports/exports/relocations, section contents, Mach-O entry/thread-state commands and universal/fat variants remain unsupported in this checkpoint. Static declarations are not observed runtime mappings. OS kernel I/O is not claimed to be forcibly interruptible.\n'
if '### Bounded binary header metadata' not in read(path): changes[path] = read(path) + section
for path, text in changes.items():
    if text != (root / path).read_text(): (root / path).write_text(text); print(f"Registered: {path}")
