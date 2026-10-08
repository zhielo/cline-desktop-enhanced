import assert from "node:assert/strict";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import {
	ownedDescendantMetadata,
	startAcceptanceProcess,
	verifyRestartInstructions,
} from "../apps/vscode/scripts/desktop-installed-acceptance.ts";

test("native Node child receives exact per-process WebView2 environment and reports exit/output", async () => {
	const profile = "owned fixture profile with spaces";
	const flags =
		"--remote-debugging-port=12345 --remote-debugging-address=127.0.0.1";
	const child = startAcceptanceProcess(
		process.execPath,
		[
			"-e",
			`
		process.stdout.write(JSON.stringify({profile: process.env.WEBVIEW2_USER_DATA_FOLDER,
			flags: process.env.WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS,
			optIn: process.env.CLINE_INSTALLED_ACCEPTANCE}));
		process.stderr.write("owned startup diagnostic");
		process.exitCode = 7;
	`,
		],
		process.cwd(),
		{
			...process.env,
			CLINE_INSTALLED_ACCEPTANCE: "1",
			WEBVIEW2_USER_DATA_FOLDER: profile,
			WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS: flags,
		},
	);
	assert.equal(await child.exited, 7);
	await child.closed;
	assert.deepEqual(JSON.parse(child.diagnostics.stdoutTail), {
		profile,
		flags,
		optIn: "1",
	});
	assert.equal(child.diagnostics.stderrTail, "owned startup diagnostic");
	assert.equal(child.diagnostics.launchError, "");
});
test("native Node launch failure is observed instead of becoming an unhandled error", async () => {
	const child = startAcceptanceProcess(
		join(tmpdir(), "owned-missing-executable-7bdb0c7f"),
		[],
		process.cwd(),
		process.env,
	);
	assert.equal(await child.exited, null);
	await child.closed;
	assert.match(child.diagnostics.launchError, /ENOENT/);
});
test("native Node process output retention is bounded", async () => {
	const child = startAcceptanceProcess(
		process.execPath,
		[
			"-e",
			`
		process.stdout.write("x".repeat(32768));
		process.stderr.write("y".repeat(32768));
	`,
		],
		process.cwd(),
		process.env,
	);
	assert.equal(await child.exited, 0);
	await child.closed;
	assert.equal(child.diagnostics.stdoutTail.length, 16384);
	assert.equal(child.diagnostics.stderrTail.length, 16384);
});

test("restart assertion waits for enabled hydrated UI and still rejects data loss", async () => {
	let ready = false;
	const instructions = {
		async click(options) {
			assert.deepEqual(options, { trial: true, timeout: 30000 });
			ready = true;
		},
		async inputValue() {
			assert.equal(ready, true);
			return "persisted";
		},
	};
	await verifyRestartInstructions(instructions, "persisted");
	await assert.rejects(
		verifyRestartInstructions(instructions, "lost"),
		/did not survive restart/,
	);
	await assert.rejects(
		verifyRestartInstructions(
			{
				async click() {
					throw new Error("not hydrated");
				},
			},
			"persisted",
		),
		/not hydrated/,
	);
});
test("descendant diagnostics reject recycled parent PIDs and unrelated processes", () => {
	const row = (pid, parentPid, createdAt) => ({
		name: "owned",
		pid,
		parentPid,
		createdAt,
		debuggingArgumentObserved: false,
		ownedProfileObserved: false,
	});
	const snapshot = [
		row(40, 1, "2026-10-08T12:00:00Z"),
		row(41, 40, "2026-10-08T12:00:01Z"),
		row(42, 41, "2026-10-08T12:00:02Z"),
		row(9, 40, "2026-10-07T00:00:00Z"),
		row(10, 9, "2026-10-08T12:01:00Z"),
		row(43, 41, "invalid"),
		row(90, 1, "2026-10-08T12:01:00Z"),
	];
	assert.deepEqual(
		ownedDescendantMetadata(snapshot, 40, "2026-10-08T12:00:00Z", "owned").map(
			(p) => p.pid,
		),
		[41, 42],
	);
	assert.deepEqual(
		ownedDescendantMetadata(snapshot, 40, "2026-10-09T12:00:00Z", "owned"),
		[],
	);
	assert.deepEqual(
		ownedDescendantMetadata(snapshot, 40, "2026-10-08T12:00:00Z", "foreign"),
		[],
	);
	assert.deepEqual(
		ownedDescendantMetadata(snapshot, 999, "2026-10-08T12:00:00Z", "owned"),
		[],
	);
	assert.deepEqual(
		ownedDescendantMetadata(
			[row(40, 1, "invalid")],
			40,
			"2026-10-08T12:00:00Z",
			"owned",
		),
		[],
	);
});
