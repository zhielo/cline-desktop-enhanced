import { gzipSync } from "node:zlib";
import * as path from "node:path";
import {
	EvidenceArchiveManifestSchema,
	EvidenceArchiveOptionsSchema,
} from "../investigation-workflows-schema";
import {
	assertNewCandidate,
	candidateHash,
	publishCandidate,
	readCandidateFile,
} from "./candidate-files";
import {
	prepareProcessEnvironment,
	redactSensitiveText,
} from "./process-environment-policy";
/** Portable gzip JSON container; selected text only, no recursive directory harvesting. */
export async function exportEvidenceArchive(
	input: { target?: string; output_file?: string; evidence_archive?: unknown },
	signal?: AbortSignal,
) {
	if (!input.target || !input.output_file?.endsWith(".json.gz"))
		throw new Error(
			"Select an explicit manifest and a distinct new .json.gz archive output",
		);
	const options = EvidenceArchiveOptionsSchema.parse(input.evidence_archive);
	const manifestBytes = await readCandidateFile(
		input.target,
		1024 * 1024,
		signal,
	);
	if (candidateHash(manifestBytes) !== options.manifest_sha256)
		throw new Error("Evidence manifest hash mismatch");
	const manifest = EvidenceArchiveManifestSchema.parse(
		JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(manifestBytes)),
	);
	await assertNewCandidate(input.target, input.output_file);
	const root = path.dirname(input.target),
		ids = new Set<string>(),
		paths = new Set<string>(),
		secrets = prepareProcessEnvironment().secretValues;
	const entries: {
		id: string;
		kind: string;
		format: string;
		sourceSha256: string;
		exportedSha256: string;
		sourceBytes: number;
		exportedBytes: number;
		redacted: boolean;
		content: string;
	}[] = [];
	let total = 0;
	for (const entry of manifest.entries) {
		signal?.throwIfAborted();
		const file = path.resolve(root, entry.path),
			relative = path.relative(root, file),
			key = process.platform === "win32" ? file.toLowerCase() : file;
		if (
			path.isAbsolute(entry.path) ||
			entry.path.includes("\\") ||
			!relative ||
			relative === ".." ||
			relative.startsWith(`..${path.sep}`) ||
			path.isAbsolute(relative) ||
			ids.has(entry.id) ||
			paths.has(key)
		)
			throw new Error(
				"Evidence entries require unique IDs and confined relative files",
			);
		ids.add(entry.id);
		paths.add(key);
		const raw = await readCandidateFile(file, 1024 * 1024, signal);
		total += raw.length;
		if (total > 8 * 1024 * 1024)
			throw new Error("Evidence archive aggregate budget exceeded");
		if (candidateHash(raw) !== entry.sha256)
			throw new Error("Evidence entry hash mismatch");
		const text = new TextDecoder("utf-8", { fatal: true }).decode(raw);
		if (text.includes("\u0000"))
			throw new Error("Evidence archive accepts text only");
		let content: string;
		if (entry.format === "json") {
			let nodes = 0;
			const redact = (value: unknown, depth: number): unknown => {
				if (++nodes > 20000 || depth > 32)
					throw new Error("Evidence JSON structural budget exceeded");
				if (typeof value === "string")
					return redactSensitiveText(value, secrets);
				if (Array.isArray(value)) return value.map((v) => redact(v, depth + 1));
				if (value && typeof value === "object")
					return Object.fromEntries(
						Object.entries(value).map(([k, v]) => [
							redactSensitiveText(k, secrets),
							/(?:token|secret|password|authorization|credential|private.?key|api.?key)/i.test(
								k,
							)
								? "[REDACTED]"
								: redact(v, depth + 1),
						]),
					);
				return value;
			};
			content = JSON.stringify(redact(JSON.parse(text), 0));
		} else content = redactSensitiveText(text, secrets);
		entries.push({
			id: entry.id,
			kind: entry.kind,
			format: entry.format,
			sourceSha256: entry.sha256,
			exportedSha256: candidateHash(content),
			sourceBytes: raw.length,
			exportedBytes: Buffer.byteLength(content),
			redacted: content !== text,
			content,
		});
	}
	const document = {
		schemaVersion: 1,
		protocol: "cline-evidence-archive/v1",
		title: redactSensitiveText(manifest.title, secrets),
		manifestSha256: options.manifest_sha256,
		entries,
		provenance:
			"Hash-bound imported entries; producer/tool versions inside receipts are claims, not authenticated attestations.",
		redaction: {
			policy: "selected-text-known-secrets-and-credential-patterns/v1",
			originalPathsIncluded: false,
			rawBinaryIncluded: false,
			completeSecretRemovalGuaranteed: false,
		},
		limitations: [
			"Selected finding/receipt/log/limitations entries only, not every investigation file or a producer-authenticated chain of custody.",
			"Known environment secrets, credential patterns and sensitive JSON keys are redacted. Unknown secrets may remain; review before external sharing.",
			"Source hashes describe originals; exported hashes describe redacted content. Redaction can remove useful evidence. No source executes or changes.",
		],
	};
	const raw = Buffer.from(JSON.stringify(document));
	if (raw.length > 12 * 1024 * 1024)
		throw new Error("Evidence archive serialization budget exceeded");
	signal?.throwIfAborted();
	const archive = gzipSync(raw, { level: 6 });
	signal?.throwIfAborted();
	const publication = await publishCandidate(
		input.target,
		input.output_file,
		options.manifest_sha256,
		archive,
		signal,
	);
	return {
		schemaVersion: 1,
		status: "completed",
		effect: "candidate-write",
		published: true,
		outputSha256: candidateHash(archive),
		bytes: archive.length,
		uncompressedBytes: raw.length,
		entryCount: entries.length,
		manifestSha256: options.manifest_sha256,
		observedExecution: false,
		limitations: document.limitations,
		...publication,
	};
}
