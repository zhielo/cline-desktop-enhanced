import { ProcessSessionManager } from "../src/extensions/tools/executors/process-session-manager";

const OWNER = "terminal-smoke";
const manager = new ProcessSessionManager();
const bun = (
	globalThis as {
		Bun?: {
			sleep(milliseconds: number): Promise<void>;
			which(executable: string): string | null;
		};
	}
).Bun;

if (!bun) {
	throw new Error("The terminal smoke test must run under Bun");
}
const bunRuntime = bun;

async function waitForCompletion(processId: string): Promise<void> {
	const deadline = Date.now() + 10_000;
	while (Date.now() < deadline) {
		const state = manager.get(OWNER, processId)?.state;
		if (state === "exited") return;
		if (state === "failed" || state === "cancelled") {
			throw new Error(
				`Interactive process ended in unexpected state: ${state}`,
			);
		}
		await bunRuntime.sleep(10);
	}
	throw new Error("Interactive process did not complete");
}

async function waitForOutput(
	processId: string,
	expected: string,
): Promise<void> {
	const deadline = Date.now() + 10_000;
	while (Date.now() < deadline) {
		const output = manager
			.read(OWNER, processId)
			.chunks.map((chunk) => chunk.text)
			.join("");
		if (output.includes(expected)) return;
		const state = manager.get(OWNER, processId)?.state;
		if (state === "exited" || state === "failed" || state === "cancelled") {
			throw new Error(
				`Interactive process ended before ${expected}: ${JSON.stringify(output)}`,
			);
		}
		await bunRuntime.sleep(10);
	}
	throw new Error(`Interactive process did not report ${expected}`);
}

try {
	const bunExecutable = bunRuntime.which("bun");
	if (!bunExecutable) {
		throw new Error("The terminal smoke test requires Bun on PATH");
	}
	const started = await manager.start({
		ownerSessionId: OWNER,
		executable: bunExecutable,
		args: [
			"-e",
			'console.log("tty:" + process.stdin.isTTY + ":" + process.stdout.isTTY); process.stdin.resume(); process.stdin.once("data", chunk => { console.log("input:" + Buffer.from(chunk).toString().replace(/[\\r\\n]+/g, "")); process.exit(0); }); console.log("ready:input");',
		],
		cwd: process.cwd(),
		interactive: true,
		columns: 90,
		rows: 30,
	});
	if (
		!started.interactive ||
		started.terminalColumns !== 90 ||
		started.terminalRows !== 30
	) {
		throw new Error("Interactive terminal metadata is incorrect");
	}
	await waitForOutput(started.processId, "ready:input");
	manager.resize(OWNER, started.processId, 100, 40);
	await bunRuntime.sleep(100);
	await manager.writeStdin(OWNER, started.processId, "ping\r");
	await waitForCompletion(started.processId);
	const output = manager
		.read(OWNER, started.processId)
		.chunks.map((chunk) => chunk.text)
		.join("");
	if (!output.includes("tty:true:true")) {
		throw new Error(
			`Child did not observe a real terminal: ${JSON.stringify(output)}`,
		);
	}
	if (!output.includes("input:ping")) {
		throw new Error(
			`Terminal input was not delivered: ${JSON.stringify(output)}`,
		);
	}
	console.log(
		`Native ${process.platform === "win32" ? "ConPTY" : "PTY"} smoke test passed`,
	);
} finally {
	await manager.dispose();
}
