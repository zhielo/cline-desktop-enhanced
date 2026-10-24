import { constants } from "node:fs";
import { lstat, open, realpath } from "node:fs/promises";
import path from "node:path";
import {
	ANALYSIS_PROFILE,
	byteDigest,
	ResultSchema,
	type AnalysisResult,
} from "../contracts";
import { confinedTarget } from "../worker";
import {
	ArtifactReaderRequestSchema,
	ArtifactMetadataReportSchema,
} from "./contracts";
import { readGoBinaryImage } from "./upstream/src/go/GoBinaryImage";
import { readRustBinaryImage } from "./upstream/src/rust/RustBinaryImage";
import { readIl2cppMetadata } from "./upstream/src/il2cpp/Il2cppMetadataFile";
import { readPyInstallerInventory } from "./pyinstaller";
const MAX_BYTES = 32 * 1024 * 1024;
export async function readOwnedArtifactBytes(
	workspace: string,
	target: string,
	expectedSha256: string,
	maxBytes = MAX_BYTES,
) {
	const resolved = await confinedTarget(workspace, target);
	const handle = await open(
		resolved,
		constants.O_RDONLY |
			(process.platform === "win32" ? 0 : constants.O_NOFOLLOW),
	);
	let bytes: Buffer;
	try {
		const before = await handle.stat();
		if (!before.isFile() || before.size > maxBytes)
			throw new Error("Artifact input exceeds fixed regular-file byte budget");
		const buffer = Buffer.alloc(before.size + 1);
		let count = 0;
		while (count < buffer.length) {
			const r = await handle.read(buffer, count, buffer.length - count, count);
			if (!r.bytesRead) break;
			count += r.bytesRead;
		}
		const after = await handle.stat(),
			named = await lstat(resolved);
		if (
			count !== before.size ||
			!named.isFile() ||
			named.isSymbolicLink() ||
			["dev", "ino", "size", "mtimeMs", "ctimeMs"].some(
				(k) =>
					before[k as keyof typeof before] !== after[k as keyof typeof after] ||
					after[k as keyof typeof after] !== named[k as keyof typeof named],
			) ||
			(await realpath(resolved)) !== resolved
		)
			throw new Error("Metadata artifact changed during read");
		bytes = buffer.subarray(0, count);
	} finally {
		await handle.close();
	}
	const sha256 = byteDigest(bytes);
	if (sha256 !== expectedSha256)
		throw new Error("Metadata artifact SHA256 changed since selection");
	return { bytes, resolved, sha256 };
}
/** Worker-only byte admission. No executable, plugin, interpreter or target is launched. */
export async function inspectOwnedArtifactMetadata(
	workspace: string,
	target: string,
	value: unknown,
): Promise<AnalysisResult> {
	const request = ArtifactReaderRequestSchema.parse(value);
	const { bytes, resolved, sha256 } = await readOwnedArtifactBytes(
		workspace,
		target,
		request.expectedSha256,
	);
	let decoded: unknown;
	if (request.reader === "go") decoded = readGoBinaryImage(bytes);
	else if (request.reader === "rust") decoded = readRustBinaryImage(bytes);
	else if (request.reader === "pyinstaller")
		decoded = readPyInstallerInventory(bytes);
	else
		decoded = readIl2cppMetadata(bytes, {
			beforeRows: (counts) => {
				if (Object.values(counts).reduce((a, b) => a + b, 0) > 20000)
					throw new Error("IL2CPP row budget exceeded");
			},
			beforeText: (n) => {
				if (n > 1024 * 1024) throw new Error("IL2CPP string budget exceeded");
			},
		});
	const records: Array<{ path: string; valueJson: string }> = [];
	let visited = 0,
		omitted = 0,
		outputBytes = 0;
	const walk = (v: unknown, p: string, depth: number) => {
		if (++visited > 50000)
			throw new Error("Metadata projection visit budget exceeded");
		if (depth > 32 || p.length > 1024) {
			omitted++;
			return;
		}
		if (v !== null && typeof v === "object" && Object.keys(v).length) {
			for (const [k, x] of Object.entries(v))
				walk(
					x,
					`${p}/${k.replace(/~/g, "~0").replace(/\//g, "~1")}`,
					depth + 1,
				);
			return;
		}
		const valueJson = JSON.stringify(v);
		if (valueJson === undefined) return;
		const n = Buffer.byteLength(valueJson) + Buffer.byteLength(p) + 64;
		if (
			records.length >= 2048 ||
			valueJson.length > 8192 ||
			outputBytes + n > 1024 * 1024
		) {
			omitted++;
			return;
		}
		outputBytes += n;
		records.push({ path: p || "/", valueJson });
	};
	walk(decoded, "", 0);
	const report = ArtifactMetadataReportSchema.parse({
		protocol: "cline-artifact-metadata/1",
		reader: request.reader,
		inputSha256: sha256,
		upstreamRevision: "f9fabdfcb2c241b18fec0acb5c3b4a14f76f4805",
		records,
		visited,
		omitted,
		truncated: omitted > 0,
		targetExecuted: false,
		limitations: [
			"Static metadata observations only; absence is not a language verdict and embedded metadata can be forged.",
			"Go/Rust native containers and IL2CPP metadata versions 24, 27, 29, 31, 39 use attributed pinned REA pure readers. This is not REA runtime parity.",
			"32 MiB input, fixed parser-child deadline, 20,000 IL2CPP rows, 2,048 retained scalar records and 1 MiB projection. Omitted records remain explicit; no implicit retry.",
			...(request.reader === "pyinstaller"
				? [
						"CArchive cookie/TOC inventory only; no nested PYZ, decompilation, decompression, extraction or target execution.",
					]
				: []),
		],
	});
	return ResultSchema.parse({
		profile: ANALYSIS_PROFILE,
		parserVersion: "artifact-metadata/f9fabdfc-1",
		status: "partial",
		artifacts: [
			{
				path: path.relative(workspace, resolved).split(path.sep).join("/"),
				sha256,
				bytes: bytes.length,
				role: "artifact-metadata-input",
			},
		],
		facts: [],
		edges: [],
		limitations: report.limitations,
		counters: { entries: 1, bytes: bytes.length, nodes: records.length },
		artifactMetadata: report,
	});
}
