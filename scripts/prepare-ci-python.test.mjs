import assert from "node:assert/strict";
import { realpathSync } from "node:fs";
import test from "node:test";
import {
	parsePythonIdentity,
	prepareCiPython,
	PYTHON_PROBE,
} from "./prepare-ci-python.mjs";
const value = {
	protocol: "cline-ci-python/v1",
	executable: process.execPath,
	version: [3, 13, 0],
};
test("accepts and canonicalizes a bounded absolute interpreter identity", () => {
	assert.deepEqual(parsePythonIdentity(JSON.stringify(value)), {
		...value,
		executable: realpathSync.native(process.execPath),
	});
});
test("rejects malformed, oversized and unsupported identities", () => {
	for (const s of [
		"{",
		"x".repeat(4097),
		"null",
		JSON.stringify({ ...value, protocol: "other" }),
		JSON.stringify({ ...value, version: [2, 7, 0] }),
		JSON.stringify({ ...value, version: [3, 13] }),
		JSON.stringify({ ...value, version: [3, "13", 0] }),
	])
		assert.throws(() => parsePythonIdentity(s));
});
test("rejects relative, missing and control-containing executable paths", () => {
	for (const executable of [
		"python.exe",
		`${process.execPath}\nX=unsafe`,
		`${process.execPath}\0`,
		`${process.execPath}.missing`,
	])
		assert.throws(() =>
			parsePythonIdentity(JSON.stringify({ ...value, executable })),
		);
});
test("rejects command-channel control characters before process creation", () => {
	assert.throws(
		() => prepareCiPython("python\nunsafe"),
		/Invalid CI Python executable/,
	);
});
test("initializes only stdlib, not application fixtures or target code", () => {
	assert.ok(PYTHON_PROBE.includes("CI_PYTHON_PHASE=entry"));
	assert.ok(PYTHON_PROBE.includes("CI_PYTHON_PHASE=stdlib-ready"));
	assert.ok(!PYTHON_PROBE.includes("android-investigation"));
	assert.ok(!PYTHON_PROBE.includes("runpy"));
});
