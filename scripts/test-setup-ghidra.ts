// CI-only real Setup Center acceptance. Requires pinned Ghidra and compatible JDK.
// No target execution; no external output acknowledgement or global root override.
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { mkdir, readFile, rm, realpath } from "node:fs/promises";
import { tmpdir } from "node:os";
import { isAbsolute, join, relative, resolve, sep } from "node:path";
import {
	currentGhidraAcceptance,
	saveSetupPreferences,
	testGhidraIntegration,
} from "../apps/examples/desktop-app/sidecar/setup-center";

const home = process.env.GHIDRA_HOME;
if (!home)
	throw new Error(
		"Real Setup Center acceptance requires GHIDRA_HOME and compatible JDK",
	);
const data = resolve(`.cline-setup-owned-${randomUUID()}`);
const temp = await realpath(tmpdir());
await mkdir(data, { mode: 0o700 });
const canonicalData = await realpath(data);
const offset = relative(temp, canonicalData);
if (
	!offset ||
	(offset !== ".." && !offset.startsWith(`..${sep}`) && !isAbsolute(offset))
) {
	await rm(data, { recursive: true, force: true });
	throw new Error(
		"Setup acceptance data must be outside OS temp to reproduce the original output-boundary failure",
	);
}
const envNames = [
	"CLINE_DATA_DIR",
	"CLINE_GHIDRA_SELECTED_HOME",
	"GHIDRA_HOME",
	"IDA_HOME",
	"CLINE_IDA_SELECTED_HOME",
	"CLINE_ANALYSIS_SANDBOX_WORKER",
	"CLINE_ANALYSIS_SANDBOX_PUBLIC_KEY",
	"ADB_PATH",
];
const previous = new Map(envNames.map((name) => [name, process.env[name]]));
try {
	process.env.CLINE_DATA_DIR = canonicalData;
	await saveSetupPreferences({ schemaVersion: 1, ghidraHome: home });
	const receipt = await testGhidraIntegration();
	assert.equal(
		receipt.status,
		"passed",
		`Real Setup Center Ghidra test failed: ${String(receipt.error ?? "missing receipt")}`,
	);
	assert.equal(
		await currentGhidraAcceptance(receipt, home),
		true,
		"Actual Setup Center receipt is not current",
	);
	const saved = JSON.parse(
		await readFile(
			join(canonicalData, "setup-center", "ghidra-receipt.json"),
			"utf8",
		),
	);
	assert.equal(saved.status, "passed");
	assert.equal(saved.javaSha256, receipt.javaSha256);
	assert.equal(saved.fixtureSha256, receipt.fixtureSha256);
	console.log(
		"Real Setup Center Ghidra owned-function acceptance passed; durable non-temp receipt, temporary engine project, Java identity verified; target not executed",
	);
} finally {
	for (const [name, value] of previous) {
		if (value === undefined) delete process.env[name];
		else process.env[name] = value;
	}
	// This directory contains only owned setup metadata, never the engine project.
	await rm(data, { recursive: true, force: true });
}
