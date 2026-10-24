import { expect, it } from "vitest";
import { spawn } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { privateProcessGroupGone } from "./private-process-group";
const pause = (ms: number) => new Promise((r) => setTimeout(r, ms));
it("never probes reserved or malformed process groups", () => {
	for (const id of [-1, 0, 1, NaN, Infinity, 1.5])
		expect(privateProcessGroupGone(id)).toBe(false);
});
it.runIf(process.platform === "linux")(
	"requires group absence, not just a dead original leader",
	async () => {
		const root = await mkdtemp(join(tmpdir(), "cline-group-proof-"));
		const marker = join(root, "child.pid");
		const stop = join(root, "stop");
		const ready = join(root, "ready");
		const leader = spawn(
			process.execPath,
			[
				"-e",
				`const {spawn}=require('node:child_process');const {writeFileSync,existsSync}=require('node:fs');const c=spawn(process.execPath,['-e',${JSON.stringify(`const fs=require('node:fs');fs.writeFileSync(${JSON.stringify(ready)},'ready');setTimeout(()=>process.exit(0),15000);setInterval(()=>{if(fs.existsSync(${JSON.stringify(stop)}))process.exit(0)},50);`)}],{stdio:'ignore'});writeFileSync(${JSON.stringify(marker)},String(c.pid));setTimeout(()=>process.exit(1),10000);setInterval(()=>{if(existsSync(${JSON.stringify(ready)}))process.exit(0)},10);`,
			],
			{ detached: true, stdio: "ignore" },
		);
		try {
			await new Promise<void>((resolve, reject) => {
				leader.once("error", reject);
				leader.once("exit", (code) =>
					code === 0
						? resolve()
						: reject(new Error("Owned group fixture failed")),
				);
			});
			expect(Number(await readFile(marker, "utf8"))).toBeGreaterThan(1);
			expect(privateProcessGroupGone(leader.pid!)).toBe(false);
			// Some container init processes do not reap orphan zombies. Absence-only
			// recovery correctly remains blocked in that case; never pretend leader
			// exit alone proves all descendants gone.
			await writeFile(stop, "done");
			await pause(150);
		} finally {
			// No PID/group kill. Signal only our private stop file; the owned child
			// also has a finite fallback lifetime even if the test process dies.
			await writeFile(stop, "done");
			await pause(150);
			await rm(root, { recursive: true, force: true });
		}
	},
);

it.runIf(process.platform === "linux")(
	"reports absence after reaping an owned childless private leader",
	async () => {
		const leader = spawn(
			process.execPath,
			[
				"-e",
				"process.stdin.resume();process.stdin.on('end',()=>process.exit(0));setTimeout(()=>process.exit(1),15000)",
			],
			{ detached: true, stdio: ["pipe", "ignore", "ignore"] },
		);
		const done = new Promise<void>((resolve, reject) => {
			leader.once("error", reject);
			leader.once("exit", () => resolve());
		});
		try {
			expect(privateProcessGroupGone(leader.pid!)).toBe(false);
		} finally {
			leader.stdin?.end();
		}
		await done;
		expect(privateProcessGroupGone(leader.pid!)).toBe(true);
	},
);
