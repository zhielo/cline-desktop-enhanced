import { createHash, randomUUID } from "node:crypto";
import * as fs from "node:fs/promises";
import * as path from "node:path";
import { SmaliPatchSchema } from "../analysis-commands";

const MAX_SOURCE_BYTES = 512 * 1024;
const hash = (data: string | Buffer) =>
	createHash("sha256").update(data).digest("hex");
const methods = (source: string) => [
	...source.matchAll(
		/^\.method[^\r\n]*\r?\n[\s\S]*?^\.end method[\t ]*(?=\r?$)/gm,
	),
];
function signature(method: string) {
	return method.split(/\r?\n/, 1)[0]?.trim().split(/\s+/).at(-1);
}
async function rejectLinks(candidate: string, allowMissingLeaf: boolean) {
	let current = path.resolve(candidate);
	let leaf = true;
	for (;;) {
		try {
			const stat = await fs.lstat(current);
			if (stat.isSymbolicLink())
				throw new Error("Smali patch paths must not contain symbolic links");
		} catch (error) {
			if (
				!(
					leaf &&
					allowMissingLeaf &&
					(error as NodeJS.ErrnoException).code === "ENOENT"
				)
			)
				throw error;
		}
		const parent = path.dirname(current);
		if (parent === current) break;
		current = parent;
		leaf = false;
	}
}

/** Single-file candidate operation, not a project rewriter or a bytecode verifier. */
export async function smaliPatch(
	input: {
		operation: string;
		target?: string;
		output_file?: string;
		smali_patch?: unknown;
	},
	signal?: AbortSignal,
) {
	const patch = SmaliPatchSchema.parse(input.smali_patch);
	const apply = input.operation !== "preview_smali_patch";
	const source = input.target;
	const output = input.output_file;
	if (
		!source ||
		!path.isAbsolute(source) ||
		path.extname(source).toLowerCase() !== ".smali"
	)
		throw new Error("Smali patch requires an absolute .smali source file");
	if (
		!output ||
		!path.isAbsolute(output) ||
		path.extname(output).toLowerCase() !== ".smali" ||
		path.resolve(source) === path.resolve(output)
	)
		throw new Error(
			"Choose a different new absolute .smali output_file, including for preview",
		);
	signal?.throwIfAborted();
	await rejectLinks(source, false);
	await rejectLinks(output, true);
	try {
		await fs.lstat(output);
		throw new Error("Candidate output already exists; no overwrite permitted");
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
	}
	const handle = await fs.open(source, "r");
	let bytes: Buffer;
	try {
		const stat = await handle.stat();
		if (!stat.isFile() || stat.size > MAX_SOURCE_BYTES)
			throw new Error("Smali source must be a file no larger than 512 KiB");
		const buffer = Buffer.alloc(MAX_SOURCE_BYTES + 1);
		let used = 0;
		while (used < buffer.length) {
			signal?.throwIfAborted();
			const read = await handle.read(buffer, used, buffer.length - used, used);
			if (!read.bytesRead) break;
			used += read.bytesRead;
		}
		if (used > MAX_SOURCE_BYTES)
			throw new Error("Smali source exceeds byte budget");
		bytes = buffer.subarray(0, used);
	} finally {
		await handle.close();
	}
	if (hash(bytes) !== patch.expected_sha256)
		throw new Error("Smali input hash changed; obtain a fresh preview");
	const text = new TextDecoder("utf-8", {
		fatal: true,
		ignoreBOM: true,
	}).decode(bytes);
	if (
		[text, patch.expected_method, patch.replacement_method].some((value) =>
			value.includes("\0"),
		)
	)
		throw new Error("NUL bytes are not accepted in Smali text");
	const classes = [
		...text.matchAll(/^\.class[^\r\n]*\s(L[^\s;]+;)[\t ]*\r?$/gm),
	];
	if (classes.length !== 1 || classes[0]?.[1] !== patch.class_descriptor)
		throw new Error("Exact Smali class descriptor did not match");
	const matches = methods(text).filter(
		(match) => signature(match[0]) === patch.method_signature,
	);
	if (matches.length !== 1 || matches[0]?.[0] !== patch.expected_method)
		throw new Error(
			"Expected exactly one unchanged method body; ambiguous or stale patch rejected",
		);
	const replacement = methods(patch.replacement_method);
	if (
		replacement.length !== 1 ||
		replacement[0]?.[0] !== patch.replacement_method ||
		signature(patch.replacement_method) !== patch.method_signature ||
		/^\.(class|super|field|method)\b/gm.test(
			patch.replacement_method.slice(
				patch.replacement_method.indexOf("\n") + 1,
			),
		)
	)
		throw new Error(
			"Replacement must be exactly one method with the same signature, without class or field directives",
		);
	if (patch.expected_method === patch.replacement_method)
		throw new Error("Patch contains no change");
	const match = matches[0];
	if (!match || match.index === undefined)
		throw new Error("Exact method location unavailable");
	const candidate =
		text.slice(0, match.index) +
		patch.replacement_method +
		text.slice(match.index + match[0].length);
	const candidateHash = hash(candidate);
	const previewHash = hash(
		JSON.stringify({
			version: 1,
			source: path.resolve(source),
			output: path.resolve(output),
			input: patch.expected_sha256,
			class: patch.class_descriptor,
			method: patch.method_signature,
			before: patch.expected_method,
			after: patch.replacement_method,
		}),
	);
	const result = {
		operation: input.operation,
		status: "completed",
		source,
		inputSha256: patch.expected_sha256,
		candidateOutputFile: output,
		candidateSha256: candidateHash,
		previewSha256: previewHash,
		classDescriptor: patch.class_descriptor,
		methodSignature: patch.method_signature,
		validation: "not-run",
		published: false,
		diff: { before: patch.expected_method, after: patch.replacement_method },
		limitations: [
			"Exact single-method text replacement only; not parser-backed register/control-flow repair.",
			"One candidate .smali file, not a copied project. Integrate into a separate candidate tree and assemble before use.",
			"No assembly, ART verification, signing, installation, or execution occurred.",
			"Static filesystem checks are not an operating-system sandbox.",
		],
	};
	if (!apply) return result;
	if (patch.preview_sha256 !== previewHash)
		throw new Error(
			"Apply requires the matching preview_sha256; target, method and destination must be unchanged",
		);
	signal?.throwIfAborted();
	await rejectLinks(source, false);
	await rejectLinks(output, true);
	// Re-read using the same bounded reader to reject changes since preview without unbounded allocation.
	const reread = await fs.open(source, "r");
	try {
		const buffer = Buffer.alloc(MAX_SOURCE_BYTES + 1);
		let used = 0;
		while (used < buffer.length) {
			signal?.throwIfAborted();
			const read = await reread.read(buffer, used, buffer.length - used, used);
			if (!read.bytesRead) break;
			used += read.bytesRead;
		}
		if (
			used > MAX_SOURCE_BYTES ||
			hash(buffer.subarray(0, used)) !== patch.expected_sha256
		)
			throw new Error("Source changed during patch preparation");
	} finally {
		await reread.close();
	}
	const temporary = path.join(
		path.dirname(output),
		`.cline-smali-${randomUUID()}.tmp`,
	);
	let published = false;
	try {
		const file = await fs.open(temporary, "wx", 0o600);
		try {
			await file.writeFile(candidate, "utf8");
			await file.sync();
		} finally {
			await file.close();
		}
		signal?.throwIfAborted();
		// Hard-link publication is atomic and fails if destination exists. Never use overwrite rename.
		await fs.link(temporary, output);
		published = true;
		return {
			...result,
			published,
			outputFile: output,
			outputSha256: candidateHash,
		};
	} finally {
		await fs.rm(temporary, { force: true });
	}
}
