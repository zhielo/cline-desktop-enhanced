import { afterEach, expect, it, vi } from "vitest";
import {
	mkdtemp,
	realpath,
	writeFile,
	readFile,
	rm,
	symlink,
} from "node:fs/promises";
import path from "node:path";
import { tmpdir } from "node:os";
import { runFirstPartyAnalysis, cancelFirstPartyAnalysis } from "../service";
import * as engineModule from "./engine";
import { runOwnedGeneralRecovery } from "./owned-run";
import { FirstPartyAnalysisStore } from "../store";
import {
	byteDigest,
	digest,
	ANALYSIS_PROFILE,
	type AnalysisReceipt,
} from "../contracts";
import { queryFirstPartyEvidence } from "../index";
import { exportSavedBundleRecovery } from "../bundle-recovery-export";
import { randomUUID } from "node:crypto";
const original = process.env.CLINE_BUNDLED_ANALYSIS_ROOT;
const pinned = process.env.CLINE_TEST_WAKARU_ROOT;
const roots: string[] = [];
afterEach(async () => {
	vi.restoreAllMocks();
	if (original === undefined) delete process.env.CLINE_BUNDLED_ANALYSIS_ROOT;
	else process.env.CLINE_BUNDLED_ANALYSIS_ROOT = original;
	for (const root of roots.splice(0))
		await rm(root, { recursive: true, force: true });
});
async function fixture() {
	const root = await realpath(
		await mkdtemp(path.join(tmpdir(), "cline-owned-general-")),
	);
	roots.push(root);
	const file = path.join(root, "bundle.js");
	const bytes = Buffer.from(
		"(function(modules){function r(id){var m={exports:{}};modules[id](m,m.exports,r);return m.exports;}return r(0);})({0:function(module,exports,require){var x=require(1);module.exports=x+1;},1:function(module){module.exports=41;}});",
	);
	await writeFile(file, bytes);
	const store = new FirstPartyAnalysisStore(path.join(root, "test.sqlite"));
	store.setMode("owner", root, "static");
	const input = {
		target: file,
		bundleRecovery: {
			engine: "wakaru" as const,
			expectedSha256: byteDigest(bytes),
		},
	};
	return { root, file, bytes, store, input };
}
it("missing general engines fail explicitly without silently falling back to literal recovery", async () => {
	const { store, input } = await fixture();
	delete process.env.CLINE_BUNDLED_ANALYSIS_ROOT;
	try {
		const receipt = await runFirstPartyAnalysis(
			"owner",
			input,
			undefined,
			store,
			JSON.stringify({ executable: process.execPath, args: [] }),
		);
		expect(receipt.status).toBe("failed");
		expect(receipt.result).toBeUndefined();
		expect(receipt.error).toContain("no fallback");
		expect(store.get("owner", receipt.id).status).toBe("failed");
	} finally {
		store.close();
	}
});
it.skipIf(!pinned)(
	"owns native recovery directly and retains queryable, separately exportable provenance",
	async () => {
		const { root, file, bytes, store, input } = await fixture();
		process.env.CLINE_BUNDLED_ANALYSIS_ROOT = pinned;
		try {
			const receipt = await runFirstPartyAnalysis(
				"owner",
				input,
				undefined,
				store,
				JSON.stringify({ executable: process.execPath, args: [] }),
			);
			expect(receipt.status, receipt.error).toBe("partial");
			expect(receipt.pid).toBeGreaterThan(1);
			expect(receipt.result?.bundleRecovery?.engine).toBe("wakaru/1.14.0");
			expect(receipt.result?.bundleRecovery?.modules).toHaveLength(2);
			expect(receipt.resultHash).toBe(digest(receipt.result));
			const before = store.get("owner", receipt.id);
			store.setMode("owner", root, "off");
			delete process.env.CLINE_BUNDLED_ANALYSIS_ROOT;
			const page = queryFirstPartyEvidence(
				"owner",
				{ receiptId: receipt.id, view: "bundle-recovery", limit: 5 },
				store,
			) as {
				available: boolean;
				reportHash: string;
				providerCalls: number;
				items: unknown[];
			};
			expect(page.available).toBe(true);
			expect(page.providerCalls).toBe(0);
			expect(page.items).toHaveLength(2);
			expect(() =>
				queryFirstPartyEvidence(
					"other",
					{ receiptId: receipt.id, view: "bundle-recovery" },
					store,
				),
			).toThrow();
			const output = path.join(root, "recovered.json");
			await exportSavedBundleRecovery(
				"owner",
				file,
				output,
				{ receiptId: receipt.id, reportHash: page.reportHash },
				undefined,
				store,
			);
			const saved = JSON.parse(await readFile(output, "utf8"));
			expect(saved.report).toEqual(receipt.result?.bundleRecovery);
			expect(saved.report.targetExecuted).toBe(false);
			await expect(
				exportSavedBundleRecovery(
					"owner",
					file,
					output,
					{ receiptId: receipt.id, reportHash: page.reportHash },
					undefined,
					store,
				),
			).rejects.toThrow("exists");
			expect(await readFile(file)).toEqual(bytes);
			expect(store.get("owner", receipt.id)).toEqual(before);
			// Rehashed envelopes cannot publish corrupt module provenance.
			for (const field of ["source", "range"] as const) {
				const corrupt = structuredClone(before);
				const report = corrupt.result?.bundleRecovery;
				if (!report || report.engine !== "wakaru/1.14.0")
					throw new Error("Expected native fixture report");
				if (field === "source")
					report.modules[0].sourceBase64 =
						Buffer.from("corrupt").toString("base64");
				else report.modules[0].ranges[0].sha256 = "0".repeat(64);
				corrupt.resultHash = digest(corrupt.result);
				const corruptedView = {
					get: () => corrupt,
				} as unknown as FirstPartyAnalysisStore;
				await expect(
					exportSavedBundleRecovery(
						"owner",
						file,
						path.join(root, `corrupt-${field}.json`),
						{ receiptId: receipt.id, reportHash: digest(report) },
						undefined,
						corruptedView,
					),
				).rejects.toThrow(/identity mismatch|provenance mismatch/);
			}
			await writeFile(file, "changed");
			await expect(
				exportSavedBundleRecovery(
					"owner",
					file,
					path.join(root, "changed.json"),
					{ receiptId: receipt.id, reportHash: page.reportHash },
					undefined,
					store,
				),
			).rejects.toThrow("SHA256");
		} finally {
			store.close();
		}
	},
	process.platform === "win32" ? 90000 : 30000,
);
it("pre-cancelled owning native requests do not spawn or retain successful evidence", async () => {
	const { root, store, input } = await fixture();
	const abort = new AbortController();
	abort.abort();
	const receipt: AnalysisReceipt = {
		id: randomUUID(),
		sessionId: "owner",
		workspace: root,
		profile: ANALYSIS_PROFILE,
		input,
		requestHash: digest(input),
		createdAt: new Date().toISOString(),
		status: "running",
	};
	store.start(receipt);
	try {
		const result = await runOwnedGeneralRecovery(receipt, store, abort);
		expect(result.status).toBe("cancelled");
		expect(result.pid).toBeUndefined();
		expect(result.result).toBeUndefined();
		expect(store.get("owner", receipt.id).status).toBe("cancelled");
	} finally {
		store.close();
	}
});

it.skipIf(!pinned)(
	"cancels the actual owning native process without cross-session permission or success evidence",
	async () => {
		const { file, bytes, store, input } = await fixture();
		process.env.CLINE_BUNDLED_ANALYSIS_ROOT = pinned;
		const actual = engineModule.runPinnedGeneralRecovery;
		const launched = vi
			.spyOn(engineModule, "runPinnedGeneralRecovery")
			.mockImplementation((source, sha, signal, onSpawn) =>
				actual(source, sha, signal, (pid) => {
					onSpawn?.(pid);
					const running = store
						.summaries("owner")
						.find((r) => r.status === "running");
					if (!running || typeof running.id !== "string")
						throw new Error(
							"Owning reservation missing before native cancellation",
						);
					const receiptId = running.id;
					expect(() => cancelFirstPartyAnalysis(receiptId, "other")).toThrow(
						"owned active worker",
					);
					cancelFirstPartyAnalysis(receiptId, "owner");
				}),
			);
		try {
			const receipt = await runFirstPartyAnalysis(
				"owner",
				input,
				undefined,
				store,
				JSON.stringify({ executable: process.execPath, args: [] }),
			);
			expect(launched).toHaveBeenCalledOnce();
			expect(["cancelled", "termination-unconfirmed"]).toContain(
				receipt.status,
			);
			expect(receipt.result).toBeUndefined();
			expect(receipt.resultHash).toBeUndefined();
			expect(store.get("owner", receipt.id).status).toBe(receipt.status);
			expect(await readFile(file)).toEqual(bytes);
			expect(() => cancelFirstPartyAnalysis(receipt.id, "owner")).toThrow(
				"owned active worker",
			);
		} finally {
			store.close();
		}
	},
	process.platform === "win32" ? 90000 : 30000,
);

it.skipIf(!pinned || process.platform === "win32")(
	"labels native receipt artifacts against the canonical workspace rather than an alias spelling",
	async () => {
		const { root, store, input } = await fixture();
		const alias = path.join(root, "workspace-alias");
		await symlink(root, alias, "dir");
		process.env.CLINE_BUNDLED_ANALYSIS_ROOT = pinned;
		const receipt: AnalysisReceipt = {
			id: randomUUID(),
			sessionId: "owner",
			workspace: alias,
			profile: ANALYSIS_PROFILE,
			input,
			requestHash: digest(input),
			createdAt: new Date().toISOString(),
			status: "running",
		};
		// Projection-only alias fixture; production ledger admission remains covered above.
		const projectionStore = {
			save: vi.fn(),
		} as unknown as FirstPartyAnalysisStore;
		try {
			const result = await runOwnedGeneralRecovery(
				receipt,
				projectionStore,
				new AbortController(),
			);
			expect(result.status, result.error).toBe("partial");
			expect(result.result?.artifacts[0].path).toBe("bundle.js");
		} finally {
			store.close();
		}
	},
	30000,
);
