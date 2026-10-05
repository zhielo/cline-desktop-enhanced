#!/usr/bin/env python3
"""Register the real pure-arithmetic native adapter on the fresh source branch."""
import os
import re
import subprocess
from pathlib import Path
root = Path(__file__).resolve().parents[1]
branch = os.environ.get("GITHUB_REF_NAME") or subprocess.check_output(["git", "branch", "--show-current"], cwd=root, text=True).strip()
if branch != "work/full-tool-platform-upgrade":
    raise SystemExit("Source writes are restricted to the upgrade branch")
changes = {}
def read(path):
    return changes.get(path, (root / path).read_text())
def replace(path, old, new):
    text = read(path)
    if text.count(new) == 1:
        return
    if text.count(old) != 1:
        raise SystemExit(f"Refusing ambiguous adapter registration: {path}")
    changes[path] = text.replace(old, new, 1)
base = "sdk/packages/core/src/extensions/tools/"
replace(base + "types.ts", '\t| "tool_registry"', '\t| "tool_registry"\n\t| "address_translate"')
replace(base + "types.ts", '\tcommandConcurrency?: number;', '\tcommandConcurrency?: number;\n\t/** Pure supplied-table address arithmetic; standard presets opt in. */\n\tenableAddressTranslate?: boolean;')
replace(base + "constants.ts", '\tTOOL_REGISTRY: "tool_registry",', '\tADDRESS_TRANSLATE: "address_translate",\n\tTOOL_REGISTRY: "tool_registry",')
replace(base + "constants.ts", '\tDefaultToolNames.TOOL_REGISTRY,', '\tDefaultToolNames.ADDRESS_TRANSLATE,\n\tDefaultToolNames.TOOL_REGISTRY,')
replace(base + "permission-profile.ts", '\t"tool_registry",', '\t"tool_registry",\n\t"address_translate",')
replace(base + "definitions.ts", 'import { isAbsolute, join, resolve } from "node:path";', 'import { createAddressTranslateTool } from "./address-translate";\nimport { isAbsolute, join, resolve } from "node:path";')
replace(base + "definitions.ts", '\t\tenableToolRegistry = false,', '\t\tenableAddressTranslate = false,\n\t\tenableToolRegistry = false,')
replace(base + "definitions.ts", '\tif (enableToolRegistry) {', '\tif (enableAddressTranslate) tools.push(createAddressTranslateTool());\n\tif (enableToolRegistry) {')
for path in [base + "index.ts", "sdk/packages/core/src/index.ts"]:
    export = 'export { createAddressTranslateTool } from "' + ('./address-translate' if path == base + 'index.ts' else './extensions/tools/address-translate') + '";'
    if export not in read(path):
        changes[path] = read(path) + '\n' + export + '\n'
presets = base + "presets.ts"
text = read(presets)
if 'enableAddressTranslate:' not in text:
    text, count = re.subn(r'(?m)^(\t\t)enableToolRegistry: true,', r'\1enableAddressTranslate: true,\n\1enableToolRegistry: true,', text)
    if count < 3:
        raise SystemExit("Cannot safely identify tool presets")
    changes[presets] = text
for path in [base + "runtime.ts", base + "model-tool-routing.ts"]:
    text = read(path)
    if '| "enableAddressTranslate"' not in text:
        text = text.replace('| "enableToolRegistry"', '| "enableAddressTranslate"\n\t\t| "enableToolRegistry"')
        changes[path] = text
    replace(path, '\ttool_registry: "enableToolRegistry",', '\taddress_translate: "enableAddressTranslate",\n\ttool_registry: "enableToolRegistry",')
runtime = base + "runtime.ts"
replace(runtime, '\t\theadlessToolNames: ["web_search"],', '\t\theadlessToolNames: ["web_search"],')
text = read(runtime)
entry = '\t{ id: "address_translate", description: "BigInt-safe supplied-table VA, RVA and file-offset translation with explicit ambiguity and zero-fill evidence.", headlessToolNames: ["address_translate"] },\n'
if entry not in text:
    needle = '\t{\n\t\tid: "web_search",'
    if text.count(needle) != 1:
        raise SystemExit("Cannot safely extend native catalog")
    changes[runtime] = text.replace(needle, entry + needle, 1)
ledger = 'CUSTOMIZATIONS.md'
section = '\n### BigInt native address translation\n\n- The registered `address_translate` adapter performs real bounded unsigned-64-bit arithmetic on supplied segment tables. It requires an explicit image base for RVA input, uses half-open ranges, reports ambiguous/unmapped mappings and never invents file offsets for zero-filled memory.\n- Tables and image bases remain user-supplied, not independently verified binary or ASLR evidence. Up to 128 segment records are accepted; matches are capped at 16 with a truthful total and truncation flag. No binary is read or executed.\n- This implements one native arithmetic adapter, not the complete native tool pack or the consolidated Windows release.\n'
if '### BigInt native address translation' not in read(ledger):
    changes[ledger] = read(ledger) + section
verifier = 'scripts/verify-custom-fork.ts'
replace(verifier, '}> = [\n', '}> = [\n\t{ path: "sdk/packages/core/src/extensions/tools/address-translate.ts", markers: ["createAddressTranslateTool", "user_supplied_segments", "zero_filled", "MAX_ADDRESS"] },\n')
for path, text in changes.items():
    if text != (root / path).read_text():
        (root / path).write_text(text)
        print(f"Registered: {path}")
