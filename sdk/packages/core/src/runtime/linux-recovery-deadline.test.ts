import { expect, it } from "vitest";
import { spawn } from "node:child_process";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
const pause = (ms: number) => new Promise((r) => setTimeout(r, ms));
it.runIf(process.platform === "linux")(
	"native-owner wall deadline survives loss of its launching host",
	async () => {
		const root = await mkdtemp(
			join(tmpdir(), "cline-independent-native-deadline-"),
		);
		const marker = join(root, "owned-child.pid");
		const childCode = `require('node:fs').writeFileSync(${JSON.stringify(marker)},String(process.pid));setTimeout(()=>process.exit(0),10000);`;
		const hostCode = `const c=require('node:child_process').spawn('/usr/bin/timeout',['--signal=KILL','3s','/usr/bin/prlimit','--cpu=4:5','--',process.execPath,'-e',${JSON.stringify(childCode)}],{detached:true,stdio:'ignore'});c.unref();process.exit(0);`;
		const host = spawn(process.execPath, ["-e", hostCode], { stdio: "ignore" });
		try {
			const exit = await new Promise<number | null>((resolve, reject) => {
				host.once("error", reject);
				host.once("exit", resolve);
			});
			expect(exit).toBe(0);
			let pid: number | undefined;
			const began = Date.now();
			while (Date.now() - began < 2500) {
				try {
					pid = Number(await readFile(marker, "utf8"));
					break;
				} catch {
					await pause(20);
				}
			}
			expect(pid).toBeGreaterThan(1);
			let stopped = false;
			while (Date.now() - began < 6500) {
				try {
					const raw = await readFile(`/proc/${pid}/stat`, "utf8");
					// A zombie is stopped, but still blocks absence-only reservation recovery.
					if (raw.slice(raw.lastIndexOf(")") + 2).startsWith("Z ")) {
						stopped = true;
						break;
					}
				} catch (error) {
					if ((error as NodeJS.ErrnoException).code === "ENOENT") {
						stopped = true;
						break;
					}
					throw error;
				}
				await pause(30);
			}
			expect(stopped).toBe(true);
		} finally {
			// The independent 3-second deadline owns cleanup; never kill an unproved PID.
			await pause(3100);
			await rm(root, { recursive: true, force: true });
		}
	},
	15000,
);
