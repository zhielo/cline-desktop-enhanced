import { execFile } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { expect, it } from "vitest";
import {
	WINDOWS_JOB_SOURCE,
	windowsJobInvocation,
} from "./windows-job-launcher";

// CI recorded a 30,265 ms native invocation timeout, not an argv assertion failure.
// The previous log did not retain the exact internal startup phase.
// A bounded 60s startup guard retains real native execution; errors expose exit/kill details.
async function runNativeFixture(
	executable: string,
	args: string[],
	options: { cwd?: string; timeout: number; maxBuffer: number },
) {
	try {
		return await promisify(execFile)(executable, args, options);
	} catch (error) {
		const failure = error as {
			code?: unknown;
			signal?: unknown;
			killed?: unknown;
			stdout?: string;
			stderr?: string;
		};
		throw new Error(
			`Native Windows fixture failed: ${JSON.stringify({
				code: failure.code,
				signal: failure.signal,
				killed: failure.killed,
				stdout: String(failure.stdout ?? "").slice(-4096),
				stderr: String(failure.stderr ?? "").slice(-4096),
			})}`,
		);
	}
}

it("uses suspended launch before assignment and has no hard-limit fallback", () => {
	expect(WINDOWS_JOB_SOURCE.indexOf("if(!CreateProcess")).toBeLessThan(
		WINDOWS_JOB_SOURCE.indexOf("if(!AssignProcess"),
	);
	expect(WINDOWS_JOB_SOURCE.indexOf("if(!AssignProcess")).toBeLessThan(
		WINDOWS_JOB_SOURCE.indexOf("if(ResumeThread"),
	);
	if (process.platform !== "win32")
		expect(() => windowsJobInvocation("node", [], "/tmp", 512, 4)).toThrow(
			"no silent",
		);
});
it.runIf(process.platform === "win32")(
	"launches a real Windows job and preserves spaced native argv",
	async () => {
		const root = await mkdtemp(join(tmpdir(), "native job fixture "));
		try {
			const invocation = windowsJobInvocation(
					process.execPath,
					[
						"-e",
						"process.stdout.write(JSON.stringify(process.argv.slice(1)))",
						"space value",
						'quote"value',
						"tail\\",
					],
					root,
					512,
					4,
				),
				result = await runNativeFixture(
					invocation.executable,
					invocation.args,
					{ cwd: root, timeout: 60000, maxBuffer: 65536 },
				);
			expect(JSON.parse(result.stdout)).toEqual([
				"space value",
				'quote"value',
				"tail\\",
			]);
		} finally {
			await rm(root, { recursive: true, force: true });
		}
	},
	75000,
);
// A Windows Job Object violation may synchronously throw UNKNOWN or emit an error event.
// The two-process control must actually run this identical owned child, so unrelated spawn failure cannot pass.
function processLimitProbe(
	spawnExpression = "require('node:child_process').spawn",
) {
	return `const spawn=${spawnExpression};let settled=false;
 function finish(value){if(settled)return;settled=true;process.stdout.write(JSON.stringify(value));process.exitCode=value.kind==='unexpected-exit'?1:0;}
 function denied(error){finish({kind:'denied',code:error.code,syscall:error.syscall,delivery:'handled'});}
 try{const child=spawn(process.execPath,['-e',"process.stdout.write('owned-child-ran')"]);let output='';
 child.stdout.on('data',data=>{output+=data;});child.on('error',denied);
 child.on('close',code=>finish({kind:code===0&&output==='owned-child-ran'?'spawned':'unexpected-exit',code,output}));
 }catch(error){denied(error);}`;
}
it("handles synchronous and asynchronous spawn denials without swallowing unexpected child exits", async () => {
	const probes = [
		"()=>{const e=new Error('owned fixture denial');e.code='UNKNOWN';e.syscall='spawn';throw e;}",
		"()=>{const {EventEmitter}=require('node:events');const c=new EventEmitter();c.stdout=new EventEmitter();queueMicrotask(()=>{const e=new Error('owned fixture denial');e.code='EACCES';e.syscall='spawn';c.emit('error',e);c.emit('close',-1);});return c;}",
	];
	for (const probe of probes) {
		const result = await runNativeFixture(
			process.execPath,
			["-e", processLimitProbe(probe)],
			{ timeout: 10000, maxBuffer: 65536 },
		);
		expect(JSON.parse(result.stdout)).toMatchObject({
			kind: "denied",
			syscall: "spawn",
			delivery: "handled",
		});
	}
	const control = await promisify(execFile)(
		process.execPath,
		["-e", processLimitProbe()],
		{ timeout: 10000, maxBuffer: 65536 },
	);
	expect(JSON.parse(control.stdout)).toMatchObject({
		kind: "spawned",
		code: 0,
		output: "owned-child-ran",
	});
});
it.runIf(process.platform === "win32")(
	"enforces active-process limits rather than reporting logical limits",
	async () => {
		const run = async (maxProcesses: number) => {
			const invocation = windowsJobInvocation(
				process.execPath,
				["-e", processLimitProbe()],
				process.cwd(),
				512,
				maxProcesses,
			);
			const result = await runNativeFixture(
				invocation.executable,
				invocation.args,
				{ timeout: 60000, maxBuffer: 65536 },
			);
			return JSON.parse(result.stdout);
		};
		const permitted = await run(2);
		expect(permitted).toMatchObject({
			kind: "spawned",
			code: 0,
			output: "owned-child-ran",
		});
		const blocked = await run(1);
		expect(blocked).toMatchObject({
			kind: "denied",
			syscall: "spawn",
			delivery: "handled",
		});
		expect(["UNKNOWN", "EPERM", "EACCES"]).toContain(blocked.code);
	},
	135000,
);
