#!/usr/bin/env python3
"""Small verified follow-up bindings for the fresh foundation, never main."""
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
        raise SystemExit(f"Refusing ambiguous refinement: {path}")
    changes[path] = text.replace(old, new, 1)
base = "sdk/packages/core/src/extensions/tools/"
routing = base + "model-tool-routing.ts"
replace(routing, '\t\t| "enableReadFiles"', '\t\t| "enableToolRegistry"\n\t\t| "enableReadFiles"')
replace(routing, '\tread_files: "enableReadFiles",', '\ttool_registry: "enableToolRegistry",\n\tread_files: "enableReadFiles",')
definitions = base + "definitions.ts"
replace(definitions, '\t\tname: "run_commands",', '\t\tname: "run_commands",\n\t\texecutionMode: "sequential",')
replace(definitions, '\t\tlet launchAttempted = false;', '\t\tlet launchAttempted = false;\n\t\tlet commandSettled = false;')
replace(definitions, '\t\t\t\t\temitUpdate: (update) => {', '\t\t\t\t\temitUpdate: (update) => {\n\t\t\t\t\t\tif (commandSettled || batch.signal.aborted || batch.remainingMs() <= 0) return;')
replace(definitions, '\t\t\trecordCompletion(true);', '\t\t\tcommandSettled = true;\n\t\t\trecordCompletion(true);')
replace(definitions, '\t\t} catch (error) {\n\t\t\trecordCompletion(false);', '\t\t} catch (error) {\n\t\t\tcommandSettled = true;\n\t\t\trecordCompletion(false);')
text = read(definitions)
old = '''						context.emitUpdate?.({
							...payload,
							commandIndex,
							...(!emittedCommandMetadata ? { query } : {}),
						});'''
new = '''						try {
							context.emitUpdate?.({
								...payload,
								commandIndex,
								...(!emittedCommandMetadata ? { query } : {}),
							});
						} catch {
							// A disconnected UI observer must not change process outcome.
						}'''
replace(definitions, old, new)
# All replacements are checked before writes; no partial integration on failure.
for path, text in changes.items():
    if text != (root / path).read_text():
        (root / path).write_text(text)
        print(f"Refined: {path}")
