import path from "node:path";
import {
	ANALYSIS_PROFILE,
	type AnalysisResult,
	ResultSchema,
} from "./contracts";
import { confinedTarget } from "./worker";
import { ArtifactResourceScope } from "./semantic-engine/upstream/src/artifacts/ArtifactResourceScope";
import {
	describeElectronFuseFindings,
	electronFuseReportSchema,
} from "./semantic-engine/upstream/src/domain/electron/electronFuses";
import {
	electronFuseReadLimitation,
	readElectronFuseImage,
} from "./semantic-engine/upstream/src/electron/ElectronFuseReader";

/** Runs only in the fixed, session-owned parser child. Never starts the target. */
export async function inspectOwnedElectronFuses(
	workspace: string,
	target: string,
): Promise<AnalysisResult> {
	const resolved = await confinedTarget(workspace, target);
	const resources = new ArtifactResourceScope();
	try {
		const image = await resources.run(() =>
			readElectronFuseImage(resolved, { resources }),
		);
		const findings = describeElectronFuseFindings(image.slices, image.format);
		const report = electronFuseReportSchema.parse({
			artifact: {
				selected_path: resolved,
				resolved_path: resolved,
				sha256: image.sha256,
				bytes: image.bytes,
				format: image.format,
			},
			slices: image.slices,
			runtime_implications: findings.runtime_implications,
			limitations: [
				...findings.limitations,
				electronFuseReadLimitation(),
				"One explicitly selected regular executable only. Static fuse bytes do not establish target behavior, Inspector readiness, or whole-application security.",
			],
		});
		return ResultSchema.parse({
			profile: ANALYSIS_PROFILE,
			parserVersion: "rea-electron-fuses/d0067ba3",
			status: "partial",
			artifacts: [
				{
					path: path.relative(workspace, resolved).split(path.sep).join("/"),
					sha256: image.sha256,
					bytes: image.bytes,
					role: "electron-fuse-container",
				},
			],
			facts: [],
			edges: [],
			limitations: [
				"Static executable fuse inspection only; no target execution or behavioral certification. Full wire observations are retained in electron-fuses evidence.",
			],
			counters: { entries: 1, bytes: image.bytes, nodes: 0 },
			electronFuses: report,
		});
	} finally {
		await resources.close();
	}
}
