import { createHash } from "node:crypto";
import { constants, realpathSync } from "node:fs";
import { lstat, open } from "node:fs/promises";
import path from "node:path";
import { type AnalysisReceipt, digest } from "@cline/core";
import { z } from "zod";
import type { SourceEvidenceSelection } from "../shared/source-evidence-selection";

const selectorSchema = z
	.object({
		receiptId: z.string().uuid(),
		selector: z.discriminatedUnion("kind", [
			z
				.object({
					kind: z.literal("fact"),
					factId: z.string().regex(/^ev_[a-f0-9]{64}$/),
				})
				.strict(),
			z
				.object({
					kind: z.literal("artifact"),
					path: z.string().min(1).max(4096),
				})
				.strict(),
		]),
	})
	.strict();
const sha = (bytes: Uint8Array) =>
	createHash("sha256").update(bytes).digest("hex");
const contained = (root: string, file: string) => {
	const relative = path.relative(root, file);
	return (
		relative !== "" &&
		!path.isAbsolute(relative) &&
		relative !== ".." &&
		!relative.startsWith(`..${path.sep}`)
	);
};
/** Explicit bounded read of one retained source identity. No search, shell, parsing or execution. */
export async function selectSourceEvidence(
	input: unknown,
	scope: { sessionId: string; workspace: string },
	getReceipt: (sessionId: string, receiptId: string) => AnalysisReceipt,
): Promise<SourceEvidenceSelection> {
	const q = selectorSchema.parse(input),
		receipt = getReceipt(scope.sessionId, q.receiptId);
	const root = realpathSync(scope.workspace);
	if (
		receipt.id !== q.receiptId ||
		receipt.sessionId !== scope.sessionId ||
		receipt.workspace !== root
	)
		throw new Error("Source evidence ownership mismatch");
	if (!/^[a-f0-9]{64}$/.test(receipt.requestHash))
		throw new Error("Saved request identity is invalid");
	if (
		!receipt.result ||
		!receipt.resultHash ||
		!["completed", "partial"].includes(receipt.status) ||
		digest(receipt.result) !== receipt.resultHash
	)
		throw new Error("Source evidence requires an intact terminal result");
	const result = receipt.result,
		selection = q.selector;
	const fact =
		selection.kind === "fact"
			? result.facts.filter((f) => f.id === selection.factId)
			: undefined;
	if (fact && fact.length !== 1)
		throw new Error("Saved fact is missing or ambiguous");
	const location = fact?.[0]?.location;
	const selectedPath =
		selection.kind === "artifact" ? selection.path : location?.path;
	const artifacts = result.artifacts.filter((a) => a.path === selectedPath);
	if (artifacts.length !== 1)
		throw new Error("Saved artifact is missing or ambiguous");
	const artifact = artifacts[0]!;
	if (
		!/^[a-f0-9]{64}$/.test(artifact.sha256) ||
		(location && location.sha256 !== artifact.sha256)
	)
		throw new Error("Saved source identity is inconsistent");
	if (
		location &&
		(!Number.isSafeInteger(location.line) ||
			location.line < 1 ||
			!Number.isSafeInteger(location.column) ||
			location.column < 1)
	)
		throw new Error("Saved source coordinates are invalid");
	const base = {
		version: "source-evidence-selection/v1" as const,
		receiptId: receipt.id,
		requestHash: receipt.requestHash,
		resultHash: receipt.resultHash,
		sessionId: scope.sessionId,
		workspace: root,
		path: artifact.path,
		expectedSha256: artifact.sha256,
		...(fact ? { factId: fact[0]!.id } : {}),
		...(location
			? { location: { line: location.line, column: location.column } }
			: {}),
	};
	const outcome = (
		status: SourceEvidenceSelection["status"],
		note: string,
		preview?: SourceEvidenceSelection["preview"],
	): SourceEvidenceSelection => ({
		...base,
		status,
		note,
		checkedAt: new Date().toISOString(),
		...(preview ? { preview } : {}),
	});
	const name = artifact.path;
	if (name.includes("!/") || !/\.(?:[cm]?[jt]sx?|json|map)$/i.test(name))
		return outcome(
			"unsupported",
			"Virtual/archive members and non-text or native artifacts require a dedicated identity adapter; no file was read.",
		);
	if (
		!name ||
		name.length > 4096 ||
		["\\", ":", "\0", "\r", "\n"].some((c) => name.includes(c)) ||
		path.posix.isAbsolute(name) ||
		name.split("/").some((p) => !p || p === "." || p === "..")
	)
		return outcome(
			"blocked",
			"Saved path is not a confined source member; no file was read.",
		);
	const file = path.resolve(root, ...name.split("/"));
	if (!contained(root, file))
		return outcome("blocked", "Saved path escapes the owning workspace.");
	try {
		let current = root;
		for (const segment of name.split("/")) {
			current = path.join(current, segment);
			const entry = await lstat(current);
			if (entry.isSymbolicLink())
				return outcome("blocked", "Linked source paths are not followed.");
			if (current !== file && !entry.isDirectory())
				return outcome("blocked", "Source parent is not a regular directory.");
			if (current === file && (!entry.isFile() || entry.size > 1024 * 1024))
				return outcome(
					"unsupported",
					"Only regular source files up to 1 MiB can be rechecked.",
				);
		}
		if (realpathSync(file) !== file)
			return outcome("blocked", "Source path identity changed before read.");
		const handle = await open(
			file,
			constants.O_RDONLY |
				(process.platform === "win32"
					? 0
					: constants.O_NOFOLLOW | constants.O_NONBLOCK),
		);
		let bytes: Buffer;
		try {
			const before = await handle.stat();
			if (!before.isFile() || before.size > 1024 * 1024)
				return outcome(
					"unsupported",
					"Only regular source files up to 1 MiB can be rechecked.",
				);
			const buffer = Buffer.alloc(before.size + 1);
			let count = 0;
			while (count < buffer.length) {
				const r = await handle.read(
					buffer,
					count,
					buffer.length - count,
					count,
				);
				if (!r.bytesRead) break;
				count += r.bytesRead;
			}
			const after = await handle.stat(),
				actual = realpathSync(file),
				link = await lstat(file);
			if (
				actual !== file ||
				!contained(root, actual) ||
				link.isSymbolicLink() ||
				link.dev !== after.dev ||
				link.ino !== after.ino ||
				count !== before.size ||
				after.size !== before.size ||
				after.mtimeMs !== before.mtimeMs ||
				after.ctimeMs !== before.ctimeMs
			)
				return outcome(
					"unavailable",
					"Source changed during the read; no preview or freshness claim is available.",
				);
			bytes = buffer.subarray(0, count);
		} finally {
			await handle.close();
		}
		if (sha(bytes) !== artifact.sha256)
			return outcome(
				"stale",
				"Current bytes differ from saved evidence. No current source preview is shown; rerun analysis explicitly to create new evidence.",
			);
		let text: string;
		try {
			text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(
				bytes,
			);
		} catch {
			return outcome(
				"unsupported",
				"Source bytes are not supported UTF-8 text; no preview is shown.",
			);
		}
		if (text.includes("\0"))
			return outcome("unsupported", "Binary text is not previewed.");
		const all = text.split(/\r\n|[\n\r\u2028\u2029]/),
			center = location?.line ?? 1;
		if (
			center > all.length ||
			(location && location.column > all[center - 1]!.length + 1)
		)
			return outcome(
				"unavailable",
				"Saved source coordinates do not address the matching text; no approximate selection is substituted.",
			);
		const start = Math.max(1, center - 4),
			finish = Math.min(all.length, center + 4);
		const lines = all.slice(start - 1, finish).map((line, index) => ({
			line: start + index,
			text: line.slice(0, 1000),
			truncated: line.length > 1000,
		}));
		return outcome(
			"matched",
			"Bytes matched the retained SHA256 at this read. This is a bounded static source snapshot, not continuous freshness, execution proof or approval.",
			{
				lines,
				truncated:
					start > 1 || finish < all.length || lines.some((l) => l.truncated),
			},
		);
	} catch (error) {
		const code = (error as NodeJS.ErrnoException).code;
		return outcome(
			code === "ENOENT"
				? "missing"
				: code === "ELOOP"
					? "blocked"
					: "unavailable",
			code === "ENOENT"
				? "Saved source is no longer present; retained evidence remains unchanged."
				: "Source could not be safely rechecked; no freshness claim is made.",
		);
	}
}
