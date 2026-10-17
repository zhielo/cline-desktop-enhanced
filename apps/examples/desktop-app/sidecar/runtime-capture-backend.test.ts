import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, rename, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { probeProcessStartTokenAsync } from "@cline/core";
import { afterEach, expect, it } from "vitest";
import {
	assertCaptureFile,
	captureFileActivity,
	captureProcessTree,
	parseLinuxTreeRow,
	selectProcessTree,
} from "./runtime-capture-backend";

const roots: string[] = [];
afterEach(async () => {
	for (const root of roots) await rm(root, { recursive: true, force: true });
	roots.length = 0;
});
async function fixture() {
	const root = await mkdtemp(join(tmpdir(), "owned-capture-"));
	roots.push(root);
	const target = join(root, "owned.js"),
		text = "setInterval(()=>{},1000);\n";
	await writeFile(target, text);
	return {
		root,
		target,
		hash: createHash("sha256").update(text).digest("hex"),
	};
}
it("selects only bounded descendants and rejects ambiguous or older identities", () => {
	const rows = [
		{ pid: 10, parentPid: 1, birth: "50" },
		{ pid: 11, parentPid: 10, birth: "51" },
		{ pid: 12, parentPid: 11, birth: "52" },
		{ pid: 13, parentPid: 10, birth: "49" },
		{ pid: 14, parentPid: 1, birth: "60" },
	];
	expect(selectProcessTree(rows, 10, 128).processes.map((p) => p.pid)).toEqual([
		10, 11, 12,
	]);
	expect(selectProcessTree(rows, 10, 1)).toEqual({
		processes: [rows[0]],
		truncated: true,
	});
	expect(() => selectProcessTree([...rows, rows[0]!], 10, 64)).toThrow(
		"Ambiguous",
	);
	expect(() => selectProcessTree(rows, 90, 64)).toThrow("absent");
	expect(() => selectProcessTree(rows, 10, 129)).toThrow("budget");
});
it.skipIf(process.platform !== "linux")(
	"parses Linux names without disclosing command lines",
	async () => {
		const raw = await readFile(`/proc/${process.pid}/stat`, "utf8"),
			row = parseLinuxTreeRow(process.pid, raw);
		expect(row?.pid).toBe(process.pid);
		expect(Object.keys(row!)).toEqual(["pid", "parentPid", "birth"]);
		expect(parseLinuxTreeRow(process.pid + 1, raw)).toBeUndefined();
		expect(parseLinuxTreeRow(1, "invalid")).toBeUndefined();
	},
);
it.skipIf(!["linux", "win32"].includes(process.platform))(
	"captures a real owned Node PID and rejects stale birth identity",
	async () => {
		const f = await fixture(),
			child = spawn(process.execPath, [f.target], { stdio: "ignore" });
		try {
			let identity = await probeProcessStartTokenAsync(child.pid!);
			for (let i = 0; i < 20 && identity.status !== "found"; i++) {
				await new Promise((r) => setTimeout(r, 50));
				identity = await probeProcessStartTokenAsync(child.pid!);
			}
			if (identity.status !== "found")
				throw new Error("Owned fixture identity unavailable");
			const result = await captureProcessTree(
				child.pid!,
				identity.token,
				4,
				new AbortController().signal,
			);
			expect(result.processes[0]?.pid).toBe(child.pid);
			expect(result.status).toBe("partial");
			expect(JSON.stringify(result)).not.toContain(f.target);
			await expect(
				captureProcessTree(
					child.pid!,
					"stale",
					4,
					new AbortController().signal,
				),
			).rejects.toThrow("identity");
		} finally {
			child.kill();
			await new Promise<void>((r) => {
				if (child.exitCode !== null || child.signalCode !== null) r();
				else child.once("exit", () => r());
			});
		}
	},
	30000,
);
it("captures real exact-file events, not contents", async () => {
	const f = await fixture();
	const result = (await captureFileActivity(
		f.target,
		f.hash,
		1500,
		1,
		new AbortController().signal,
		() => {
			void writeFile(f.target, "PRIVATE_CONTENT_DO_NOT_CAPTURE");
		},
	)) as { events: unknown[]; stopReason: string };
	expect(result.events).toHaveLength(1);
	expect(result.stopReason).toBe("event-budget");
	expect(JSON.stringify(result)).not.toContain("PRIVATE_CONTENT");
});
it("ends at deadline without sibling notifications or completeness claims", async () => {
	const f = await fixture();
	const result = (await captureFileActivity(
		f.target,
		f.hash,
		250,
		4,
		new AbortController().signal,
		() => {
			void writeFile(join(f.root, "private-sibling.txt"), "sensitive");
		},
	)) as { events: unknown[]; status: string; stopReason: string };
	expect(result).toMatchObject({
		events: [],
		status: "partial",
		stopReason: "deadline",
	});
});
it("closes promptly on cancellation and rejects changed hashes and budgets", async () => {
	const f = await fixture(),
		controller = new AbortController();
	await expect(
		captureFileActivity(f.target, f.hash, 5000, 4, controller.signal, () =>
			controller.abort(new Error("Owned cancellation")),
		),
	).rejects.toThrow("Owned cancellation");
	await rename(f.target, join(f.root, "released.js"));
	await writeFile(f.target, "changed");
	await expect(
		assertCaptureFile(f.target, f.hash, new AbortController().signal),
	).rejects.toThrow("changed");
	await expect(
		captureFileActivity(
			f.target,
			f.hash,
			5001,
			4,
			new AbortController().signal,
		),
	).rejects.toThrow("budget");
});
it("pre-aborted capture cannot register a watcher", async () => {
	const f = await fixture(),
		controller = new AbortController();
	controller.abort(new Error("pre-aborted"));
	await expect(
		captureFileActivity(f.target, f.hash, 200, 4, controller.signal),
	).rejects.toThrow("pre-aborted");
});
