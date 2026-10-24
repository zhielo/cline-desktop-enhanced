import { expect, it } from "vitest";
import { spawn } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
	windowsJobInvocation,
	WINDOWS_JOB_SOURCE,
} from "./windows-job-launcher";

it("assigns the suspended process before resume and keeps finite recovery deadlines inside the job owner", () => {
	expect(WINDOWS_JOB_SOURCE.indexOf("if(!CreateProcess")).toBeLessThan(
		WINDOWS_JOB_SOURCE.indexOf("if(!AssignProcess"),
	);
	expect(WINDOWS_JOB_SOURCE.indexOf("if(!AssignProcess")).toBeLessThan(
		WINDOWS_JOB_SOURCE.indexOf("if(ResumeThread"),
	);
	expect(WINDOWS_JOB_SOURCE).toContain(
		"WaitForSingleObject(info.process,deadlineMs)",
	);
	expect(WINDOWS_JOB_SOURCE).toContain("if(wait==258)return 124");
	expect(WINDOWS_JOB_SOURCE).toContain("if(job!=IntPtr.Zero)CloseHandle(job)");
});
const gone = (pid: number) => {
	try {
		process.kill(pid, 0);
		return false;
	} catch (error) {
		return (error as NodeJS.ErrnoException).code === "ESRCH";
	}
};
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

it.runIf(process.platform === "win32")(
	"passes held stdin intact into a real suspended job child",
	async () => {
		const root = await mkdtemp(join(tmpdir(), "cline job stdin "));
		try {
			const launch = windowsJobInvocation(
				process.execPath,
				[
					"-e",
					"let s='';process.stdin.setEncoding('utf8');process.stdin.on('data',c=>s+=c);process.stdin.on('end',()=>process.stdout.write(JSON.stringify({received:s})));",
				],
				root,
				512,
				2,
				5000,
			);
			const child = spawn(launch.executable, launch.args, {
				stdio: ["pipe", "pipe", "pipe"],
				windowsHide: true,
				cwd: root,
			});
			let out = "";
			child.stdout.on("data", (c) => (out += c));
			child.stderr.on("data", () => {});
			const done = new Promise<number | null>((resolve, reject) => {
				child.once("error", reject);
				child.once("close", resolve);
			});
			child.stdin.end("owned request 🧪\n");
			expect(await done).toBe(0);
			expect(JSON.parse(out)).toEqual({ received: "owned request 🧪\n" });
		} finally {
			await rm(root, { recursive: true, force: true });
		}
	},
	30000,
);

it.runIf(process.platform === "win32")(
	"kills real owned descendants when the job deadline expires",
	async () => {
		const root = await mkdtemp(join(tmpdir(), "cline job deadline "));
		try {
			const source =
				"const c=require('node:child_process').spawn(process.execPath,['-e','setInterval(()=>{},1000)'],{stdio:'ignore'});process.stdout.write(JSON.stringify({pid:c.pid})+'\\n');setInterval(()=>{},1000);";
			const launch = windowsJobInvocation(
				process.execPath,
				["-e", source],
				root,
				512,
				4,
				2000,
			);
			const child = spawn(launch.executable, launch.args, {
				stdio: ["ignore", "pipe", "pipe"],
				windowsHide: true,
				cwd: root,
			});
			let out = "";
			child.stdout.on("data", (c) => (out += c));
			child.stderr.on("data", () => {});
			const code = await new Promise<number | null>((resolve, reject) => {
				child.once("error", reject);
				child.once("close", resolve);
			});
			expect(code).toBe(124);
			const pid = JSON.parse(out.trim()).pid;
			expect(Number.isInteger(pid) && pid > 0).toBe(true);
			const until = Date.now() + 5000;
			while (!gone(pid) && Date.now() < until) await sleep(25);
			expect(gone(pid)).toBe(true);
		} finally {
			await rm(root, { recursive: true, force: true });
		}
	},
	30000,
);
