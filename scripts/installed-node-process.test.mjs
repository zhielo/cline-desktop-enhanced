import assert from "node:assert/strict";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { startAcceptanceProcess } from "../apps/vscode/scripts/desktop-installed-acceptance.ts";

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
			flags: process.env.WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS}));
		process.stderr.write("owned startup diagnostic");
		process.exitCode = 7;
	`,
		],
		process.cwd(),
		{
			...process.env,
			WEBVIEW2_USER_DATA_FOLDER: profile,
			WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS: flags,
		},
	);
	assert.equal(await child.exited, 7);
	await child.closed;
	assert.deepEqual(JSON.parse(child.diagnostics.stdoutTail), {
		profile,
		flags,
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
