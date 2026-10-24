import * as groupProbe from "../../runtime/private-process-group";
import { afterEach, expect, it, vi } from "vitest";
import {
	writeFile,
	mkdir,
	mkdtemp,
	readFile,
	readdir,
	rm,
} from "node:fs/promises";
import path from "node:path";
import { tmpdir } from "node:os";
import { byteDigest } from "../contracts";
import {
	runPinnedGeneralRecovery,
	safeRecoveryName,
	GeneralRecoveryTerminationUnconfirmedError,
} from "./engine";
import { WAKARU_PINS } from "./contracts";
const previousTemp = process.env.TMPDIR;
const original = process.env.CLINE_BUNDLED_ANALYSIS_ROOT;
const scratch: string[] = [];
afterEach(async () => {
	vi.restoreAllMocks();
	if (previousTemp === undefined) delete process.env.TMPDIR;
	else process.env.TMPDIR = previousTemp;
	if (original === undefined) delete process.env.CLINE_BUNDLED_ANALYSIS_ROOT;
	else process.env.CLINE_BUNDLED_ANALYSIS_ROOT = original;
	for (const p of scratch.splice(0))
		await rm(p, { recursive: true, force: true });
});
it("rejects unsafe, aliased and Windows-reserved output names", () => {
	for (const name of [
		"../a.js",
		"/a.js",
		"C:a.js",
		"a\\b.js",
		"a//b.js",
		"./a.js",
		"a/../b.js",
		"NUL.js",
		"a/COM1.js",
		"a./b.js",
		"a.js\0",
	])
		expect(() => safeRecoveryName(name)).toThrow();
	expect(safeRecoveryName("modules/nested-1.js")).toBe("modules/nested-1.js");
});
it("requires exact bounded source bytes and independently pinned host engine", async () => {
	delete process.env.CLINE_BUNDLED_ANALYSIS_ROOT;
	await expect(
		runPinnedGeneralRecovery(Buffer.from("x"), "0".repeat(64)),
	).rejects.toThrow(/exact bounded/);
	const invalid = Buffer.from([0xff]);
	await expect(
		runPinnedGeneralRecovery(invalid, byteDigest(invalid)),
	).rejects.toThrow(/UTF-8/);
	const large = Buffer.alloc(1024 * 1024 + 1, 65);
	await expect(
		runPinnedGeneralRecovery(large, byteDigest(large)),
	).rejects.toThrow(/bounded/);
	const source = Buffer.from("let x=1;");
	await expect(
		runPinnedGeneralRecovery(source, byteDigest(source)),
	).rejects.toThrow(/unavailable|supports/);
	const root = await mkdtemp(path.join(tmpdir(), "cline-wakaru-identity-"));
	scratch.push(root);
	const platform = process.platform;
	if (platform !== "win32" && platform !== "linux") return;
	await mkdir(path.join(root, "wakaru"));
	await writeFile(
		path.join(root, "wakaru", WAKARU_PINS[platform].file),
		"not a pinned executable",
	);
	process.env.CLINE_BUNDLED_ANALYSIS_ROOT = root;
	await expect(
		runPinnedGeneralRecovery(source, byteDigest(source)),
	).rejects.toThrow(/identity/);
});
it("does not start on pre-admission cancellation", async () => {
	const abort = new AbortController();
	abort.abort();
	const source = Buffer.from("let x=1;");
	await expect(
		runPinnedGeneralRecovery(source, byteDigest(source), abort.signal),
	).rejects.toThrow();
});
const pinnedRoot = process.env.CLINE_TEST_WAKARU_ROOT;
it.skipIf(!pinnedRoot)(
	"recovers owned webpack modules through the real pinned native engine with distinct transformed/original provenance",
	async () => {
		process.env.CLINE_BUNDLED_ANALYSIS_ROOT = pinnedRoot!;
		const source = Buffer.from(
			"(function(modules){function r(id){var m={exports:{}};modules[id](m,m.exports,r);return m.exports;}return r(0);})({0:function(module,exports,require){var x=require(1);module.exports=x+1;},1:function(module){module.exports=41;}});",
		);
		const report = await runPinnedGeneralRecovery(source, byteDigest(source));
		expect(report.engine).toBe("wakaru/1.14.0");
		expect(report.resourceBoundary).toEqual(
			process.platform === "win32"
				? {
						kind: "windows-job-object-suspended-launch",
						memoryBytes: 2147483648,
						maxProcesses: 4,
						supervisorDeadlineMs: 45000,
					}
				: {
						kind: "linux-prlimit-process-group",
						addressSpaceBytes: 2147483648,
						cpuSoftSeconds: 45,
						cpuHardSeconds: 46,
						fileBytes: 67108864,
						hostDeadlineMs: 50000,
						supervisorDeadlineMs: 45000,
					},
		);
		expect(report.targetExecuted).toBe(false);
		expect(report.verifiedBehavior).toBe(false);
		expect(report.modules).toHaveLength(2);
		expect(report.detectedFormats).toContain("webpack4");
		for (const m of report.modules) {
			const text = Buffer.from(m.sourceBase64, "base64");
			expect(byteDigest(text)).toBe(m.sha256);
			for (const r of m.ranges)
				expect(byteDigest(source.subarray(r.startByte, r.endByte))).toBe(
					r.sha256,
				);
			expect(
				m.ranges.some(
					(r) => !text.equals(source.subarray(r.startByte, r.endByte)),
				),
			).toBe(true);
			expect(m.sourceMap).toBeDefined();
			const map = Buffer.from(m.sourceMap!.contentBase64, "base64");
			expect(byteDigest(map)).toBe(m.sourceMap!.sha256);
			expect(JSON.parse(map.toString()).version).toBe(3);
		}
		const platform = process.platform as keyof typeof WAKARU_PINS;
		expect(
			byteDigest(
				await readFile(
					path.join(pinnedRoot!, "wakaru", WAKARU_PINS[platform].file),
				),
			),
		).toBe(report.engineSha256);
	},
	// Outlast the fixed 50s host supervisor on cold Windows CI.
	process.platform === "win32" ? 90000 : 20000,
);

it.skipIf(!pinnedRoot || process.platform !== "linux")(
	"retains private scratch when a native leader exits but descendant absence is unconfirmed",
	async () => {
		process.env.CLINE_BUNDLED_ANALYSIS_ROOT = pinnedRoot!;
		const root = await mkdtemp(
			path.join(tmpdir(), "cline-recovery-retention-"),
		);
		scratch.push(root);
		process.env.TMPDIR = root;
		const actualProbe = groupProbe.privateProcessGroupGone;
		const probe = vi
			.spyOn(groupProbe, "privateProcessGroupGone")
			.mockReturnValue(false);
		const source = Buffer.from(
			"(function(m){return m[0]({exports:{}})})([function(module){module.exports=42;}]);",
		);
		await expect(
			runPinnedGeneralRecovery(source, byteDigest(source)),
		).rejects.toBeInstanceOf(GeneralRecoveryTerminationUnconfirmedError);
		expect(probe).toHaveBeenCalledOnce();
		// Only our simulated probe failed; the real fixed engine is already gone.
		// Never clean a possibly live native workspace in production.
		expect(actualProbe(probe.mock.calls[0][0])).toBe(true);
		const retained = await readdir(root);
		expect(retained).toHaveLength(1);
		expect(retained[0]).toMatch(/^cline-general-recovery-/);
		expect(await readFile(path.join(root, retained[0], "input.js"))).toEqual(
			source,
		);
	},
);
