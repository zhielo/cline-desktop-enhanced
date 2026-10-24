import { it, expect, beforeEach, afterEach } from "vitest";
import {
	mkdtemp,
	realpath,
	writeFile,
	rm,
	readFile,
	readdir,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomUUID } from "node:crypto";
import {
	AnalysisInputSchema,
	byteDigest,
	digest,
	type AnalysisReceipt,
} from "./contracts";
import { analyzeTarget } from "./worker";
import { FirstPartyAnalysisStore } from "./store";
import { queryFirstPartyEvidence } from "./index";
import { exportSavedBundleRecovery } from "./bundle-recovery-export";
let root: string;
beforeEach(async () => {
	root = await realpath(
		await mkdtemp(join(tmpdir(), "cline-bundle-recovery-")),
	);
});
afterEach(async () => {
	await rm(root, { recursive: true, force: true });
});
const webpack = (runtime = "webpackChunkowned") =>
	`/* owned 🧪 */\r\n(self.${runtime}=self.${runtime}||[]).push([[1],{42:function(module,exports,require){exports.value=7;throw new Error("MUST_NOT_EXECUTE")}}]);`;
async function recover(source = webpack()) {
	const bytes = Buffer.from(source);
	await writeFile(join(root, "bundle.js"), bytes);
	const input = {
		target: "bundle.js",
		bundleRecovery: { expectedSha256: byteDigest(bytes) },
	};
	const result = await analyzeTarget(root, input);
	return { bytes, input, result, report: result.bundleRecovery! };
}
for (const runtime of ["webpackChunkowned", "webpackChunkrspack"])
	it(`recovers exact inert UTF-8 factory byte ranges from ${runtime}`, async () => {
		const { bytes, report } = await recover(webpack(runtime));
		expect(report.modules).toHaveLength(1);
		const m = report.modules[0];
		expect(Buffer.from(m.sourceBase64, "base64")).toEqual(
			bytes.subarray(m.startByte, m.endByte),
		);
		expect(byteDigest(Buffer.from(m.sourceBase64, "base64"))).toBe(m.sha256);
		expect(Buffer.from(m.sourceBase64, "base64").toString()).toContain(
			"MUST_NOT_EXECUTE",
		);
		expect(report).toMatchObject({
			engine: "cline-literal-factory/1",
			targetExecuted: false,
			truncated: false,
		});
	});
it("does not invent recovery for dynamic or non-bundle source and rejects mixed modes or stale inputs", async () => {
	const { input } = await recover(
		"throw new Error('MUST_NOT_EXECUTE'); eval('never run')",
	);
	const r = await analyzeTarget(root, input);
	expect(r.bundleRecovery?.modules).toEqual([]);
	expect(r.status).toBe("partial");
	expect(() =>
		AnalysisInputSchema.parse({ ...input, semanticGraph: true }),
	).toThrow();
	await writeFile(join(root, "bundle.js"), "changed");
	await expect(analyzeTarget(root, input)).rejects.toThrow("SHA256");
});
it("reads saved module provenance in Off and publishes only a new hash-bound JSON package", async () => {
	const { input, result, report, bytes } = await recover(),
		store = new FirstPartyAnalysisStore(join(root, "store.sqlite"));
	try {
		store.setMode("owner", root, "static");
		const receipt: AnalysisReceipt = {
			id: randomUUID(),
			sessionId: "owner",
			workspace: root,
			profile: result.profile,
			input,
			requestHash: digest(input),
			createdAt: new Date().toISOString(),
			status: "running",
		};
		store.start(receipt);
		store.save({
			...receipt,
			status: "partial",
			result,
			resultHash: digest(result),
		});
		store.setMode("owner", root, "off");
		const page = queryFirstPartyEvidence(
			"owner",
			{ receiptId: receipt.id, view: "bundle-recovery", limit: 1 },
			store,
		);
		expect(page).toMatchObject({
			reportHash: digest(report),
			providerCalls: 0,
			targetExecuted: false,
			items: expect.any(Array),
		});
		const req = { receiptId: receipt.id, reportHash: digest(report) },
			output = join(root, "recovery.json");
		await expect(
			exportSavedBundleRecovery(
				"other",
				join(root, "bundle.js"),
				output,
				req,
				undefined,
				store,
			),
		).rejects.toThrow();
		await expect(
			exportSavedBundleRecovery(
				"owner",
				join(root, "bundle.js"),
				output,
				{ ...req, reportHash: "a".repeat(64) },
				undefined,
				store,
			),
		).rejects.toThrow();
		const exported = await exportSavedBundleRecovery(
			"owner",
			join(root, "bundle.js"),
			output,
			req,
			undefined,
			store,
		);
		expect(exported).toMatchObject({
			effect: "candidate-write",
			verifiedBehavior: false,
			modules: 1,
		});
		const written = await readFile(output);
		expect(byteDigest(written)).toBe(exported.output.sha256);
		expect(JSON.parse(written.toString()).report).toEqual(report);
		await expect(
			exportSavedBundleRecovery(
				"owner",
				join(root, "bundle.js"),
				output,
				req,
				undefined,
				store,
			),
		).rejects.toThrow("exists");
		expect(await readFile(join(root, "bundle.js"))).toEqual(bytes);
		await writeFile(join(root, "bundle.js"), "changed");
		await expect(
			exportSavedBundleRecovery(
				"owner",
				join(root, "bundle.js"),
				join(root, "second.json"),
				req,
				undefined,
				store,
			),
		).rejects.toThrow("SHA256");
		expect((await readdir(root)).some((p) => p.endsWith(".tmp"))).toBe(false);
	} finally {
		store.close();
	}
});
