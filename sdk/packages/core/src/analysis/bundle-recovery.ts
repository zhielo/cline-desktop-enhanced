import { z } from "zod";
import {
	ANALYSIS_PROFILE,
	byteDigest,
	digest,
	ResultSchema,
} from "./contracts";
import { readOwnedArtifactBytes } from "./artifact-readers/reader";
import { analyzeJavaScriptStaticSource } from "./semantic-engine/upstream/src/domain/javascript/javascriptStaticAnalysis";

import path from "node:path";
import {
	BUNDLE_RECOVERY_REVISION,
	BundleRecoveryRequestSchema,
	BundleRecoveryReportSchema,
} from "./bundle-recovery-contracts";
/** AST literal factories only. Recovered text is retained as inert base64, never loaded. */
export async function recoverOwnedBundle(
	workspace: string,
	target: string,
	value: unknown,
) {
	const req = BundleRecoveryRequestSchema.parse(value),
		{ bytes, resolved, sha256 } = await readOwnedArtifactBytes(
			workspace,
			target,
			req.expectedSha256,
			1024 * 1024,
		);
	const source = bytes.toString("utf8");
	if (!Buffer.from(source).equals(bytes))
		throw new Error("Bundle recovery requires exact UTF-8 source bytes");
	const analysis = analyzeJavaScriptStaticSource(source),
		modules: Array<
			z.infer<typeof BundleRecoveryReportSchema>["modules"][number]
		> = [];
	const starts = [0];
	for (let i = 0; i < source.length; i++) {
		const c = source.charCodeAt(i);
		if (c === 13) {
			if (source.charCodeAt(i + 1) === 10) i++;
			starts.push(i + 1);
		} else if (c === 10 || c === 0x2028 || c === 0x2029) starts.push(i + 1);
	}
	const offset = (p: { line: number; column: number }) => {
		const line = starts[p.line - 1];
		if (line === undefined || p.column < 0)
			throw new Error("Invalid recovered factory coordinate");
		const index = line + p.column;
		if (
			index > source.length ||
			(starts[p.line] !== undefined && index >= starts[p.line])
		)
			throw new Error("Invalid recovered factory range");
		return index;
	};
	let omitted = 0,
		totalBytes = 0;
	const seen = new Set<string>();
	for (const reg of analysis.bundler_registrations)
		for (const m of reg.modules) {
			const start = offset(m.location.start),
				end = offset(m.location.end);
			if (end <= start) throw new Error("Empty recovered factory range");
			const content = Buffer.from(source.slice(start, end));
			if (byteDigest(content) !== m.source_sha256)
				throw new Error(
					"Recovered factory content hash disagrees with AST provenance",
				);
			const startByte = Buffer.byteLength(source.slice(0, start)),
				endByte = startByte + content.length;
			const id = digest([
				sha256,
				reg.runtime,
				m.module_key,
				startByte,
				endByte,
			]);
			if (seen.has(id)) continue;
			seen.add(id);
			if (
				modules.length >= 128 ||
				totalBytes + content.length > 1024 * 1024 ||
				reg.runtime.length > 4096 ||
				m.module_key.length > 4096
			) {
				omitted++;
				continue;
			}
			totalBytes += content.length;
			modules.push({
				id,
				bundler: reg.bundler,
				runtime: reg.runtime,
				moduleKey: m.module_key,
				startByte,
				endByte,
				sha256: m.source_sha256,
				sourceBase64: content.toString("base64"),
			});
		}
	const report = BundleRecoveryReportSchema.parse({
		protocol: "cline-bundle-recovery/1",
		engine: "cline-literal-factory/1",
		upstreamRevision: BUNDLE_RECOVERY_REVISION,
		sourceSha256: sha256,
		modules,
		omitted,
		truncated: omitted > 0,
		targetExecuted: false,
		limitations: [
			"Exact AST-literal Webpack/Rspack/esbuild factory slices only; unsupported, dynamically constructed or obfuscated bundles may yield zero modules.",
			"Not Wakaru or general deobfuscation parity. Original names, complete module coverage, runnable reconstruction and runtime equivalence are not established.",
			"Half-open UTF-8 byte ranges and hashes refer to the original immutable input. Recovered fragments retain factory wrappers and untrusted text; they are never executed.",
			"Fixed parser-child lifecycle/deadline and byte/output budgets apply on Windows/Linux. This process separation is not an OS sandbox or a hard memory quota.",
		],
	});
	return ResultSchema.parse({
		profile: ANALYSIS_PROFILE,
		parserVersion: "literal-bundle-recovery/1",
		status: "partial",
		artifacts: [
			{
				path: path.relative(workspace, resolved).split(path.sep).join("/"),
				sha256,
				bytes: bytes.length,
				role: "bundle-recovery-input",
			},
		],
		facts: [],
		edges: [],
		limitations: report.limitations,
		counters: { entries: 1, bytes: bytes.length, nodes: modules.length },
		bundleRecovery: report,
	});
}
