import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { test } from "node:test";
import {
	INSTALL_TIMEOUT_MS,
	installDependencies,
	LOCKED_PLAYWRIGHT_CLI,
} from "../apps/vscode/src/test/e2e/utils/build.mjs";

test("cold-cache E2E setup requires both installations and clears its timer", async () => {
	const completed = [];
	await installDependencies({
		timeoutMs: 1000,
		vscode: async () => completed.push("vscode"),
		chromium: async () => completed.push("chromium"),
	});
	assert.deepEqual(completed.sort(), ["chromium", "vscode"]);
	assert.equal(INSTALL_TIMEOUT_MS, 360000);
	assert.equal(existsSync(LOCKED_PLAYWRIGHT_CLI), true);
	assert.match(LOCKED_PLAYWRIGHT_CLI, /[\\/]playwright[\\/]cli\.js$/);
});
test("E2E timeout identifies the pending installation and cancels the child signal", async () => {
	let signal;
	await assert.rejects(
		installDependencies({
			timeoutMs: 20,
			vscode: async () => {},
			chromium: async (value) => {
				signal = value;
				await new Promise(() => {});
			},
		}),
		/pending: Chromium/,
	);
	assert.equal(signal.aborted, true);
});
test("E2E dependency failure cannot become successful acceptance", async () => {
	await assert.rejects(
		installDependencies({
			timeoutMs: 1000,
			vscode: async () => {
				throw new Error("owned download failure");
			},
			chromium: async () => {},
		}),
		/VS Code installation failed: owned download failure/,
	);
});
