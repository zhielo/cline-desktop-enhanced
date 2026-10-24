import path from "node:path";
import { confinedTarget } from "./worker";
import {
	BundleExportRequestSchema,
	BundleRecoveryReportSchema,
} from "./bundle-recovery-contracts";
import { readOwnedArtifactBytes } from "./artifact-readers/reader";
import { byteDigest, digest, ResultSchema } from "./contracts";
import { FirstPartyAnalysisStore } from "./store";
import { publishCandidate } from "../extensions/tools/executors/candidate-files";
/** Called only after host Modify approval; export is data, never runnable installation. */
export async function exportSavedBundleRecovery(
	sessionId: string,
	target: string,
	output: string,
	input: unknown,
	signal?: AbortSignal,
	store = new FirstPartyAnalysisStore(),
) {
	const req = BundleExportRequestSchema.parse(input),
		receipt = store.get(sessionId, req.receiptId);
	const report = BundleRecoveryReportSchema.parse(
		receipt.result?.bundleRecovery,
	);
	if (
		!["completed", "partial"].includes(receipt.status) ||
		digest(report) !== req.reportHash ||
		!output.toLowerCase().endsWith(".json")
	)
		throw new Error(
			"Choose an exact saved recovery hash and a new JSON provenance output",
		);
	const workspace = await confinedTarget(receipt.workspace, ".");
	const result = ResultSchema.parse(receipt.result),
		{ bytes, resolved } = await readOwnedArtifactBytes(
			receipt.workspace,
			target,
			report.sourceSha256,
			1024 * 1024,
		);
	if (receipt.resultHash !== digest(result))
		throw new Error("Saved bundle result identity mismatch");
	if (
		(await confinedTarget(receipt.workspace, receipt.input.target)) !== resolved
	)
		throw new Error("Saved bundle target identity mismatch");
	if (
		result.artifacts.length !== 1 ||
		result.artifacts[0].path !==
			path.relative(workspace, resolved).split(path.sep).join("/") ||
		result.artifacts[0].sha256 !== report.sourceSha256
	)
		throw new Error("Saved bundle artifact identity mismatch");
	const source = (base64: string, hash: string) => {
		const content = Buffer.from(base64, "base64");
		if (content.toString("base64") !== base64 || byteDigest(content) !== hash)
			throw new Error("Saved recovered source identity mismatch");
		return content;
	};
	if (report.engine === "cline-literal-factory/1") {
		for (const m of report.modules) {
			const content = source(m.sourceBase64, m.sha256);
			if (
				m.endByte > bytes.length ||
				m.startByte >= m.endByte ||
				!content.equals(bytes.subarray(m.startByte, m.endByte))
			)
				throw new Error("Saved recovered source provenance mismatch");
		}
	} else {
		for (const m of report.modules) {
			source(m.sourceBase64, m.sha256);
			if (m.sourceMap) source(m.sourceMap.contentBase64, m.sourceMap.sha256);
			for (const r of [...m.ranges, ...m.contextRanges])
				if (
					r.startByte >= r.endByte ||
					r.endByte > bytes.length ||
					byteDigest(bytes.subarray(r.startByte, r.endByte)) !== r.sha256
				)
					throw new Error(
						"Saved transformed source original-range provenance mismatch",
					);
		}
	}

	const encoded = Buffer.from(
		JSON.stringify(
			{
				protocol: "cline-bundle-recovery-export/1",
				receiptId: receipt.id,
				resultHash: receipt.resultHash,
				reportHash: req.reportHash,
				report,
			},
			null,
			2,
		) + "\n",
	);
	if (encoded.length > 4 * 1024 * 1024)
		throw new Error("Recovery export output budget exceeded");
	signal?.throwIfAborted();
	const publication = await publishCandidate(
		resolved,
		output,
		report.sourceSha256,
		encoded,
		signal,
	);
	return {
		status: "partial",
		effect: "candidate-write",
		output: {
			path: output,
			sha256: byteDigest(encoded),
			bytes: encoded.length,
		},
		modules: report.modules.length,
		...publication,
		verifiedBehavior: false,
		limitations: [
			"New no-overwrite JSON provenance package only. Recovered source fragments are inert base64; no target execution, original-file modification or automatic promotion.",
		],
	};
}
