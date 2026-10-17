import * as path from "node:path";
import ts from "typescript";
import {
	CandidateSchema,
	ManagedMethodSchema,
} from "../advanced-candidates-schema";
import { inspectManagedPE } from "../../../analysis/dotnet";
import { decodeIL } from "../../../analysis/il";
import { canonical } from "../../../analysis/contracts";
import {
	assertNewCandidate,
	candidateHash,
	publishCandidate,
	readCandidateFile,
} from "./candidate-files";
import { inspectJvmMethod } from "./jvm-method";
export function selectedManagedMethod(bytes: Buffer, selector: unknown) {
	const { method_token } = ManagedMethodSchema.parse(selector);
	const token = `0x${Number.parseInt(method_token.slice(2), 16).toString(16)}`;
	const inspected = inspectManagedPE(bytes, 8192);
	const records = inspected.records.map((r) => ({
		...r,
		detail: JSON.parse(r.value) as Record<string, unknown>,
	}));
	const definitions = records.filter(
		(r) => r.kind === "managed-method" && r.detail.token === token,
	);
	const bodies = records.filter(
		(r) => r.kind === "managed-il" && r.detail.methodToken === token,
	);
	if (definitions.length !== 1 || bodies.length !== 1)
		throw new Error(
			"Selected managed method body unavailable within bounded metadata budget",
		);
	const body = bodies[0];
	const n = Number(body.detail.byteLength);
	if (!Number.isInteger(n) || n > 4096 || body.offset + n > bytes.length)
		throw new Error("Managed method body exceeds bounds");
	const code = bytes.subarray(body.offset, body.offset + n);
	return {
		token,
		definition: definitions[0].detail,
		offset: body.offset,
		code,
		decoded: decodeIL(code),
		records: records
			.filter((r) => r.detail.methodToken === token)
			.map((r) => ({ kind: r.kind, offset: r.offset, ...r.detail })),
		limitations: inspected.limitations,
	};
}
export function decompileManagedSelection(bytes: Buffer, selector: unknown) {
	const m = selectedManagedMethod(bytes, selector),
		instructions = m.decoded.instructions;
	const signature = m.definition.signature as
		| { status?: string; display?: string }
		| undefined;
	let bodySource: string | null = null;
	const first = instructions[0];
	if (
		m.records.some(
			(r) =>
				r.kind === "managed-stack-model" &&
				"status" in r &&
				r.status === "completed",
		) &&
		m.decoded.status === "completed" &&
		instructions.length === 2 &&
		instructions[1].opcode === "ret" &&
		signature?.status === "completed" &&
		signature.display?.startsWith("int32 (") &&
		first
	) {
		const op = m.code[0];
		const value =
			op >= 0x15 && op <= 0x1e
				? op - 0x16
				: op === 0x1f && m.code.length === 3
					? m.code.readInt8(1)
					: op === 0x20 && m.code.length === 6
						? m.code.readInt32LE(1)
						: undefined;
		if (value !== undefined) bodySource = `{ return ${value}; }`;
	}
	return {
		status: bodySource === null ? "partial" : "completed",
		methodToken: m.token,
		definition: m.definition,
		bodySource,
		representation: bodySource
			? "reconstructed-constant-Int32-body"
			: "bounded-IL-only",
		instructions,
		records: m.records,
		limitations: [
			...m.limitations,
			"Only selected two-instruction Int32 constant-return bodies reconstruct source. Other methods retain IL and partial status; not original C#, complete decompilation, CLR verification or runtime behavior.",
		],
	};
}
function primitive(n: ts.Node): boolean {
	return (
		ts.isStringLiteral(n) ||
		ts.isNumericLiteral(n) ||
		[
			ts.SyntaxKind.TrueKeyword,
			ts.SyntaxKind.FalseKeyword,
			ts.SyntaxKind.NullKeyword,
		].includes(n.kind) ||
		(ts.isPrefixUnaryExpression(n) &&
			[ts.SyntaxKind.MinusToken, ts.SyntaxKind.PlusToken].includes(
				n.operator,
			) &&
			ts.isNumericLiteral(n.operand))
	);
}
function parseSource(file: string, text: string) {
	const source = ts.createSourceFile(file, text, ts.ScriptTarget.Latest, true);
	if (
		(source as ts.SourceFile & { parseDiagnostics?: ts.Diagnostic[] })
			.parseDiagnostics?.length
	)
		throw new Error("Source has syntax diagnostics; no transform allowed");
	return source;
}
function transformLiteral(
	source: Buffer,
	file: string,
	literal: { start: number; expected: string; replacement: string },
) {
	if (!/\.(?:[cm]?[jt]s|[jt]sx)$/i.test(file))
		throw new Error("AST transform accepts JS/TS source only");
	const text = new TextDecoder("utf-8", {
		fatal: true,
		ignoreBOM: true,
	}).decode(source);
	const parsed = parseSource(file, text);
	const matches: ts.Node[] = [];
	const visit = (n: ts.Node) => {
		if (
			n.getStart(parsed) === literal.start &&
			n.getText(parsed) === literal.expected &&
			primitive(n)
		)
			matches.push(n);
		ts.forEachChild(n, visit);
	};
	visit(parsed);
	if (matches.length !== 1)
		throw new Error(
			"Expected one exact primitive AST literal at UTF-16 start offset",
		);
	const replacement = parseSource(
		"candidate.ts",
		`const __cline_literal = (${literal.replacement});`,
	);
	const statement = replacement.statements[0];
	if (
		replacement.statements.length !== 1 ||
		!statement ||
		!ts.isVariableStatement(statement)
	)
		throw new Error("Replacement must be one primitive literal");
	const expression = statement.declarationList.declarations[0].initializer;
	if (
		!expression ||
		!ts.isParenthesizedExpression(expression) ||
		!primitive(expression.expression) ||
		expression.expression.getText(replacement) !== literal.replacement
	)
		throw new Error(
			"Replacement must contain exactly one primitive literal, not executable syntax",
		);
	if (literal.expected === literal.replacement)
		throw new Error("No-op literal transform");
	const result =
		text.slice(0, literal.start) +
		literal.replacement +
		text.slice(matches[0].end);
	parseSource(file, result);
	return Buffer.from(result, "utf8");
}
export type CandidateRequest = {
	operation: string;
	target?: string;
	output_file?: string;
	candidate?: unknown;
};
/** Computes an exact candidate without publishing it. Existing-output mode is private to read-only audit. */
async function prepareCandidate(
	input: CandidateRequest,
	signal?: AbortSignal,
	auditExistingOutput = false,
) {
	const c = CandidateSchema.parse(input.candidate),
		target = input.target,
		output = input.output_file;
	if (!target || !output || !path.isAbsolute(target))
		throw new Error("Explicit absolute source and new output_file required");
	if (auditExistingOutput) {
		if (
			!path.isAbsolute(output) ||
			path.resolve(target) === path.resolve(output)
		)
			throw new Error("Choose a distinct absolute candidate output_file");
	} else await assertNewCandidate(target, output);
	const source = await readCandidateFile(target, 16 * 1024 * 1024, signal);
	if (candidateHash(source) !== c.expected_sha256)
		throw new Error("Candidate source SHA256 mismatch");
	const rawKind = input.operation
		.replace(/^preview_/, "")
		.replace(/^apply_/, "")
		.replace(/^patch_/, "");
	const kind = rawKind === "binary_patch" ? "binary" : rawKind;
	if (
		[
			c.byte_patch,
			c.byte_patches,
			c.literal,
			c.literals,
			c.managed,
			c.jvm,
		].filter((x) => x !== undefined).length !== 1
	)
		throw new Error("Exactly one candidate edit recipe required");
	let bytes = Buffer.from(source);
	let detail: unknown;
	if (["binary_patch", "binary"].includes(kind)) {
		const edits = c.byte_patch ? [c.byte_patch] : c.byte_patches;
		if (!edits) throw new Error("byte_patch or byte_patches required");
		const ordered = [...edits].sort((a, b) => a.offset - b.offset);
		let previousEnd = -1;
		let totalBytes = 0;
		for (const edit of ordered) {
			const { offset, expected_hex, replacement_hex } = edit;
			const expected = Buffer.from(expected_hex, "hex"),
				next = Buffer.from(replacement_hex, "hex");
			totalBytes += expected.length;
			if (offset < previousEnd || totalBytes > 65536)
				throw new Error(
					"Overlapping binary edits or aggregate 65536-byte budget exceeded",
				);
			if (
				expected.length !== next.length ||
				offset + expected.length > source.length ||
				!source.subarray(offset, offset + expected.length).equals(expected)
			)
				throw new Error(
					"Exact existing bytes and equal-length replacement required",
				);
			if (expected.equals(next)) throw new Error("No-op byte patch");
			next.copy(bytes, offset);
			previousEnd = offset + expected.length;
		}
		// Preserve the v1 fingerprint for legacy single-edit recipes.
		detail = c.byte_patch
			? {
					offset: c.byte_patch.offset,
					before: c.byte_patch.expected_hex.toLowerCase(),
					after: c.byte_patch.replacement_hex.toLowerCase(),
				}
			: {
					edits: ordered.map((e) => ({
						offset: e.offset,
						before: e.expected_hex.toLowerCase(),
						after: e.replacement_hex.toLowerCase(),
					})),
				};
	} else if (kind === "ast_transform") {
		const edits = c.literal ? [c.literal] : c.literals;
		if (
			!edits ||
			path.extname(target).toLowerCase() !==
				path.extname(output).toLowerCase() ||
			source.length > 1024 * 1024
		)
			throw new Error(
				"AST recipe requires matching JS/TS extension and <=1 MiB source",
			);
		const ordered = [...edits].sort((a, b) => a.start - b.start);
		let previousEnd = -1,
			totalChars = 0;
		for (const edit of ordered) {
			totalChars += edit.expected.length + edit.replacement.length;
			if (edit.start < previousEnd || totalChars > 65536)
				throw new Error(
					"Overlapping AST edits or aggregate 65536-character budget exceeded",
				);
			// Validate every original selection against the same unmodified source.
			transformLiteral(source, target, edit);
			previousEnd = edit.start + edit.expected.length;
		}
		// Descending offsets preserve all original UTF-16 positions, including length-changing edits.
		for (const edit of [...ordered].reverse())
			bytes = Buffer.from(transformLiteral(bytes, target, edit));
		if (bytes.length > 1024 * 1024)
			throw new Error("Transformed source exceeds 1 MiB budget");
		detail = c.literal ?? { edits: ordered };
	} else if (kind === "dotnet_constant") {
		if (!c.managed) throw new Error("managed constant recipe required");
		const m = selectedManagedMethod(source, {
				method_token: c.managed.method_token,
			}),
			at = c.managed.instruction_offset;
		if (
			m.decoded.status !== "completed" ||
			!m.decoded.instructions.some((i) => i.offset === at)
		)
			throw new Error("Managed instruction boundary unavailable");
		const op = m.code[at],
			value = c.managed.replacement_value;
		if (op >= 0x15 && op <= 0x1e) {
			if (op - 0x16 !== c.managed.expected_value || value < -1 || value > 8)
				throw new Error("Managed compact constant mismatch/range");
			bytes[m.offset + at] = value + 0x16;
		} else if (op === 0x1f) {
			if (
				m.code.readInt8(at + 1) !== c.managed.expected_value ||
				value < -128 ||
				value > 127
			)
				throw new Error("Managed short constant mismatch/range");
			bytes.writeInt8(value, m.offset + at + 1);
		} else if (op === 0x20) {
			if (m.code.readInt32LE(at + 1) !== c.managed.expected_value)
				throw new Error("Managed Int32 constant mismatch");
			bytes.writeInt32LE(value, m.offset + at + 1);
		} else
			throw new Error(
				"Only fixed-width ldc.i4 constant instructions are transformable",
			);
		if (value === c.managed.expected_value)
			throw new Error("No-op managed transform");
		selectedManagedMethod(bytes, { method_token: c.managed.method_token });
		detail = c.managed;
	} else if (kind === "jvm_constant") {
		if (!c.jvm) throw new Error("jvm constant recipe required");
		const m = inspectJvmMethod(source, c.jvm.method_name, c.jvm.descriptor);
		if (
			m.descriptor !== "()I" ||
			!(m.accessFlags & 8) ||
			m.exceptionCount ||
			m.codeAttributes ||
			m.bytes.length !== 2 ||
			m.bytes[1] !== 0xac ||
			m.bytes[0] < 2 ||
			m.bytes[0] > 8 ||
			m.bytes[0] - 3 !== c.jvm.expected_value ||
			m.maxStack < 1
		)
			throw new Error(
				"JVM transform supports only static ()I iconst/ireturn with no exception/nested Code attributes",
			);
		if (c.jvm.expected_value === c.jvm.replacement_value)
			throw new Error("No-op JVM transform");
		bytes[m.offset] = c.jvm.replacement_value + 3;
		inspectJvmMethod(bytes, c.jvm.method_name, c.jvm.descriptor);
		detail = c.jvm;
	} else throw new Error("Unknown fixed candidate operation");
	const descriptor = {
		version: "advanced-candidate/v1",
		kind,
		source: path.resolve(target),
		output: path.resolve(output),
		sourceHash: c.expected_sha256,
		outputHash: candidateHash(bytes),
		detail,
	};
	const previewSha256 = candidateHash(canonical(descriptor));
	const result = {
		status: "completed",
		...descriptor,
		previewSha256,
		candidateOutputFile: output,
		published: false,
		cleanupWarning: undefined as string | undefined,
		outputFile: undefined as string | undefined,
		outputSha256: undefined as string | undefined,
		validation:
			kind === "ast_transform"
				? "syntax-only"
				: kind.includes("constant")
					? "bounded-structure-only"
					: "exact-bytes-only",
		limitations: [
			"New candidate only; original preserved. No execution, installation, signing, behavior verification or automatic promotion.",
			"Binary edits do not repair relocation tables, checksums, signatures or application semantics. Managed/JVM constant changes preserve instruction width only, not verifier/type correctness.",
			"Filesystem checks are not an OS sandbox; an adversarial concurrent filesystem mutator is outside this guarantee.",
		],
	};
	return {
		result,
		bytes,
		target,
		output,
		sourceHash: c.expected_sha256,
		approvedPreview: c.preview_sha256,
	};
}
export async function auditAdvancedCandidate(
	input: CandidateRequest,
	signal?: AbortSignal,
) {
	const prepared = await prepareCandidate(input, signal, true);
	// This path only reads: it cannot publish or accept a preview as authorization.
	let actual: Buffer;
	try {
		actual = await readCandidateFile(prepared.output, 16 * 1024 * 1024, signal);
	} catch (error) {
		signal?.throwIfAborted();
		if ((error as NodeJS.ErrnoException).code === "ENOENT")
			return {
				status: "missing" as const,
				expectedOutputSha256: prepared.result.outputHash,
				sourcePreserved: true,
			};
		throw error;
	}
	const actualOutputSha256 = candidateHash(actual);
	return {
		status:
			actualOutputSha256 === prepared.result.outputHash
				? ("verified" as const)
				: ("mismatch" as const),
		expectedOutputSha256: prepared.result.outputHash,
		actualOutputSha256,
		sourcePreserved: true,
	};
}
export async function advancedCandidate(
	input: CandidateRequest,
	signal?: AbortSignal,
) {
	const { result, bytes, target, output, sourceHash, approvedPreview } =
		await prepareCandidate(input, signal);
	if (input.operation.startsWith("preview_")) return result;
	if (approvedPreview !== result.previewSha256)
		throw new Error(
			"Apply requires matching preview_sha256 binding source, output and exact edit",
		);
	const publication = await publishCandidate(
		target,
		output,
		sourceHash,
		bytes,
		signal,
	);
	return {
		...result,
		...publication,
		published: true,
		outputFile: output,
		outputSha256: candidateHash(bytes),
	};
}
