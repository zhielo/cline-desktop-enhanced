import {
	mkdtemp,
	writeFile,
	readFile,
	rm,
	stat,
	symlink,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import {
	advancedCandidate,
	decompileManagedSelection,
	selectedManagedMethod,
} from "./advanced-candidates";
import { candidateHash, readCandidateFile } from "./candidate-files";
import { ownedManaged, ownedJvm } from "./advanced-owned-fixtures";
import { inspectJvmMethod } from "./jvm-method";
import { ReverseEngineeringInputSchema } from "../schemas";
import { isAnalysisWriteOperation } from "../analysis-commands";
const cleanup = vi.hoisted(() => ({ fail: false }));
vi.mock("node:fs/promises", async (importOriginal) => {
	const actual = await importOriginal<typeof import("node:fs/promises")>();
	return {
		...actual,
		rm: async (
			file: Parameters<typeof actual.rm>[0],
			options: Parameters<typeof actual.rm>[1],
		) => {
			if (cleanup.fail && String(file).includes(".cline-candidate-"))
				throw Object.assign(new Error("owned cleanup failure"), {
					code: "EACCES",
				});
			return actual.rm(file, options);
		},
	};
});
let root: string, target: string, output: string;
beforeEach(async () => {
	root = await mkdtemp(join(tmpdir(), "cline-candidates-"));
	target = join(root, "input.bin");
	output = join(root, "output.bin");
	await writeFile(target, Buffer.from([0, 1, 2, 3]));
});
afterEach(async () => {
	await rm(root, { recursive: true, force: true });
});
const byteRecipe = {
	expected_sha256: candidateHash(Buffer.from([0, 1, 2, 3])),
	byte_patch: { offset: 1, expected_hex: "01", replacement_hex: "ff" },
};
const request = (
	operation = "preview_binary_patch",
	candidate: unknown = byteRecipe,
) => ({ operation, target, output_file: output, candidate });
it("previews and separately publishes exact binary candidate, retaining original", async () => {
	const preview = await advancedCandidate(request());
	expect(preview.published).toBe(false);
	await expect(stat(output)).rejects.toThrow();
	const applied = await advancedCandidate(
		request("patch_binary", {
			...byteRecipe,
			preview_sha256: preview.previewSha256,
		}),
	);
	expect(applied.published).toBe(true);
	expect(await readFile(output)).toEqual(Buffer.from([0, 255, 2, 3]));
	expect(await readFile(target)).toEqual(Buffer.from([0, 1, 2, 3]));
	await expect(
		advancedCandidate(
			request("patch_binary", {
				...byteRecipe,
				preview_sha256: preview.previewSha256,
			}),
		),
	).rejects.toThrow("exists");
});
it.each([
	{ ...byteRecipe, expected_sha256: "0".repeat(64) },
	{
		...byteRecipe,
		byte_patch: { ...byteRecipe.byte_patch, expected_hex: "ff" },
	},
	{
		...byteRecipe,
		byte_patch: { ...byteRecipe.byte_patch, replacement_hex: "ffff" },
	},
	{ ...byteRecipe, byte_patch: { ...byteRecipe.byte_patch, offset: 4 } },
	{
		...byteRecipe,
		byte_patch: { ...byteRecipe.byte_patch, replacement_hex: "01" },
	},
])("rejects stale source, mismatched bytes, resizing, bounds and no-op", async (candidate) => {
	await expect(
		advancedCandidate(request("preview_binary_patch", candidate)),
	).rejects.toThrow();
	await expect(stat(output)).rejects.toThrow();
});
it("binds source, edit and destination in preview", async () => {
	const p = await advancedCandidate(request());
	await expect(
		advancedCandidate({
			...request("patch_binary", {
				...byteRecipe,
				preview_sha256: p.previewSha256,
			}),
			output_file: join(root, "other.bin"),
		}),
	).rejects.toThrow("preview_sha256");
	await expect(advancedCandidate(request("patch_binary"))).rejects.toThrow(
		"preview_sha256",
	);
});
it("rejects multiple recipe substitution", async () => {
	await expect(
		advancedCandidate(
			request("preview_binary_patch", {
				...byteRecipe,
				literal: { start: 0, expected: "0", replacement: "1" },
			}),
		),
	).rejects.toThrow("Exactly one");
});
it("honors cancellation and regular-file size budgets", async () => {
	const c = new AbortController();
	c.abort();
	await expect(advancedCandidate(request(), c.signal)).rejects.toThrow();
	await expect(readCandidateFile(target, 2)).rejects.toThrow("budget");
});
it("rejects symlink input/output ancestors", async () => {
	if (process.platform === "win32") return;
	const link = join(root, "link.bin");
	await symlink(target, link);
	await expect(
		advancedCandidate({ ...request(), target: link }),
	).rejects.toThrow("symbolic");
	await symlink(root, join(root, "alias"));
	await expect(
		advancedCandidate({
			...request(),
			output_file: join(root, "alias", "new.bin"),
		}),
	).rejects.toThrow("symbolic");
});
it("replaces exactly one parser-selected literal with syntax validation", async () => {
	target = join(root, "source.ts");
	output = join(root, "candidate.ts");
	const source = "export const value = 1;\nconst same = 1;\n";
	await writeFile(target, source);
	const c = {
		expected_sha256: candidateHash(source),
		literal: { start: source.indexOf("1"), expected: "1", replacement: "2" },
	};
	const p = await advancedCandidate(request("preview_ast_transform", c));
	const a = await advancedCandidate(
		request("apply_ast_transform", { ...c, preview_sha256: p.previewSha256 }),
	);
	expect(a.validation).toBe("syntax-only");
	expect(await readFile(output, "utf8")).toBe(source.replace("= 1", "= 2"));
	expect(await readFile(target, "utf8")).toBe(source);
});
it.each([
	"1); runTarget(); (2",
	"someFunction()",
	"1 + 2",
	"1 /*comment*/",
	"/pattern/",
	"`template`",
])("rejects executable/nonprimitive AST replacement %s", async (replacement) => {
	target = join(root, "a.ts");
	output = join(root, "b.ts");
	const source = "const a = 1;";
	await writeFile(target, source);
	await expect(
		advancedCandidate(
			request("preview_ast_transform", {
				expected_sha256: candidateHash(source),
				literal: { start: 10, expected: "1", replacement },
			}),
		),
	).rejects.toThrow();
});
it("rejects malformed original source", async () => {
	target = join(root, "a.ts");
	output = join(root, "b.ts");
	const source = "const a = 1; (";
	await writeFile(target, source);
	await expect(
		advancedCandidate(
			request("preview_ast_transform", {
				expected_sha256: candidateHash(source),
				literal: { start: 10, expected: "1", replacement: "2" },
			}),
		),
	).rejects.toThrow("syntax");
});
it("selects and reconstructs only owned constant managed method", () => {
	const m = decompileManagedSelection(ownedManaged(), {
		method_token: "0x06000001",
	});
	expect(m).toMatchObject({ status: "completed", bodySource: "{ return 1; }" });
	expect(() =>
		selectedManagedMethod(ownedManaged(), { method_token: "0x06000002" }),
	).toThrow("unavailable");
});
it("patches selected managed constant without changing IL width", async () => {
	target = join(root, "owned.dll");
	output = join(root, "candidate.dll");
	const source = ownedManaged();
	await writeFile(target, source);
	const c = {
		expected_sha256: candidateHash(source),
		managed: {
			method_token: "0x06000001",
			instruction_offset: 0,
			expected_value: 1,
			replacement_value: 2,
		},
	};
	const p = await advancedCandidate(request("preview_dotnet_constant", c));
	await advancedCandidate(
		request("patch_dotnet_constant", { ...c, preview_sha256: p.previewSha256 }),
	);
	const result = await readFile(output);
	expect(result.length).toBe(source.length);
	expect(
		decompileManagedSelection(result, { method_token: "0x06000001" })
			.bodySource,
	).toBe("{ return 2; }");
});
it("rejects managed opcode/constant mismatch", async () => {
	target = join(root, "owned.dll");
	output = join(root, "candidate.dll");
	const source = ownedManaged();
	await writeFile(target, source);
	for (const instruction_offset of [0, 1])
		await expect(
			advancedCandidate(
				request("preview_dotnet_constant", {
					expected_sha256: candidateHash(source),
					managed: {
						method_token: "0x06000001",
						instruction_offset,
						expected_value: 7,
						replacement_value: 2,
					},
				}),
			),
		).rejects.toThrow();
});
it("reads and patches a bounded static JVM constant-return method", async () => {
	const source = ownedJvm();
	expect(inspectJvmMethod(source, "value", "()I").bytes).toEqual(
		Buffer.from([3, 0xac]),
	);
	target = join(root, "Owned.class");
	output = join(root, "Candidate.class");
	await writeFile(target, source);
	const c = {
		expected_sha256: candidateHash(source),
		jvm: {
			method_name: "value",
			descriptor: "()I",
			expected_value: 0,
			replacement_value: 4,
		},
	};
	const p = await advancedCandidate(request("preview_jvm_constant", c));
	await advancedCandidate(
		request("patch_jvm_constant", { ...c, preview_sha256: p.previewSha256 }),
	);
	expect(
		inspectJvmMethod(await readFile(output), "value", "()I").bytes,
	).toEqual(Buffer.from([7, 0xac]));
});
it("rejects truncated JVM structures, unknown selection and nonconstant bytecode", async () => {
	const bytes = ownedJvm();
	for (const n of [0, 10, bytes.length - 1])
		expect(() =>
			inspectJvmMethod(bytes.subarray(0, n), "value", "()I"),
		).toThrow();
	expect(() => inspectJvmMethod(bytes, "missing", "()I")).toThrow(
		"unambiguous",
	);
	const m = inspectJvmMethod(bytes, "value", "()I");
	bytes[m.offset] = 0x2a;
	target = join(root, "Owned.class");
	output = join(root, "Candidate.class");
	await writeFile(target, bytes);
	await expect(
		advancedCandidate(
			request("preview_jvm_constant", {
				expected_sha256: candidateHash(bytes),
				jvm: {
					method_name: "value",
					descriptor: "()I",
					expected_value: 0,
					replacement_value: 1,
				},
			}),
		),
	).rejects.toThrow("supports only");
});
it.each([
	"patch_binary",
	"apply_ast_transform",
	"patch_dotnet_constant",
	"patch_jvm_constant",
	"apply_candidate_batch",
])("registers %s as a write before normalization", (operation) => {
	expect(isAnalysisWriteOperation(operation)).toBe(true);
	expect(ReverseEngineeringInputSchema.parse({ operation }).operation).toBe(
		operation,
	);
});

it("reports published output even when private temporary-link cleanup fails", async () => {
	const preview = await advancedCandidate(request());
	cleanup.fail = true;
	try {
		const result = await advancedCandidate(
			request("patch_binary", {
				...byteRecipe,
				preview_sha256: preview.previewSha256,
			}),
		);
		expect(result.published).toBe(true);
		expect(result.outputFile).toBe(output);
		expect(result.cleanupWarning).toContain("published");
		expect(await readFile(output)).toEqual(Buffer.from([0, 255, 2, 3]));
	} finally {
		cleanup.fail = false;
	}
});
it("concurrent publication never overwrites the winning candidate", async () => {
	const preview = await advancedCandidate(request());
	const apply = () =>
		advancedCandidate(
			request("patch_binary", {
				...byteRecipe,
				preview_sha256: preview.previewSha256,
			}),
		);
	const results = await Promise.allSettled([apply(), apply()]);
	expect(results.filter((r) => r.status === "fulfilled")).toHaveLength(1);
	expect(results.filter((r) => r.status === "rejected")).toHaveLength(1);
	expect(await readFile(output)).toEqual(Buffer.from([0, 255, 2, 3]));
	expect(await readFile(target)).toEqual(Buffer.from([0, 1, 2, 3]));
});

it("previews and publishes disjoint multi-byte edits bound to one candidate", async () => {
	const candidate = {
		expected_sha256: byteRecipe.expected_sha256,
		byte_patches: [
			{ offset: 3, expected_hex: "03", replacement_hex: "FF" },
			{ offset: 0, expected_hex: "00", replacement_hex: "aa" },
		],
	};
	const p = await advancedCandidate(request("preview_binary_patch", candidate));
	await advancedCandidate(
		request("patch_binary", { ...candidate, preview_sha256: p.previewSha256 }),
	);
	expect(await readFile(output)).toEqual(Buffer.from([0xaa, 1, 2, 0xff]));
	expect(await readFile(target)).toEqual(Buffer.from([0, 1, 2, 3]));
});
it("rejects overlapping or mixed single/multiple byte recipes without publication", async () => {
	for (const candidate of [
		{ ...byteRecipe, byte_patches: [byteRecipe.byte_patch] },
		{
			expected_sha256: byteRecipe.expected_sha256,
			byte_patches: [byteRecipe.byte_patch, byteRecipe.byte_patch],
		},
		{ expected_sha256: byteRecipe.expected_sha256, byte_patches: [] },
	]) {
		await expect(
			advancedCandidate(request("preview_binary_patch", candidate)),
		).rejects.toThrow();
	}
	await expect(stat(output)).rejects.toThrow();
});
it("applies multi-literal changes at original UTF-16 offsets despite changed lengths and Unicode", async () => {
	target = join(root, "owned.ts");
	output = join(root, "candidate.ts");
	const source = '\ufeffconst emoji = "😀"; const a = 10; const b = false;';
	await writeFile(target, source);
	const candidate = {
		expected_sha256: candidateHash(Buffer.from(source)),
		literals: [
			{
				start: source.indexOf("false"),
				expected: "false",
				replacement: "true",
			},
			{ start: source.indexOf("10"), expected: "10", replacement: "12345" },
		],
	};
	const p = await advancedCandidate(
		request("preview_ast_transform", candidate),
	);
	await advancedCandidate(
		request("apply_ast_transform", {
			...candidate,
			preview_sha256: p.previewSha256,
		}),
	);
	expect(await readFile(output, "utf8")).toBe(
		source.replace("10", "12345").replace("false", "true"),
	);
	expect(await readFile(target, "utf8")).toBe(source);
});
it("rejects overlapping AST ranges, syntax injection and stale multi-edit previews", async () => {
	target = join(root, "owned.ts");
	output = join(root, "candidate.ts");
	const source = "const a = -1; const b = 2;";
	await writeFile(target, source);
	const first = {
		start: source.indexOf("-1"),
		expected: "-1",
		replacement: "3",
	};
	const candidate = {
		expected_sha256: candidateHash(Buffer.from(source)),
		literals: [
			first,
			{ start: source.indexOf("2"), expected: "2", replacement: "4" },
		],
	};
	await expect(
		advancedCandidate(
			request("preview_ast_transform", {
				...candidate,
				literals: [first, first],
			}),
		),
	).rejects.toThrow("Overlapping");
	await expect(
		advancedCandidate(
			request("preview_ast_transform", {
				...candidate,
				literals: [{ ...first, replacement: "run()" }],
			}),
		),
	).rejects.toThrow("primitive");
	const p = await advancedCandidate(
		request("preview_ast_transform", candidate),
	);
	await expect(
		advancedCandidate(
			request("apply_ast_transform", {
				...candidate,
				literals: [first],
				preview_sha256: p.previewSha256,
			}),
		),
	).rejects.toThrow("preview_sha256");
	await expect(stat(output)).rejects.toThrow();
});
it("enforces aggregate multi-edit byte budgets and 32-edit cardinality", async () => {
	const bytes = Buffer.alloc(65538);
	await writeFile(target, bytes);
	const edit = {
		offset: 0,
		expected_hex: "00".repeat(32769),
		replacement_hex: "ff".repeat(32769),
	};
	await expect(
		advancedCandidate(
			request("preview_binary_patch", {
				expected_sha256: candidateHash(bytes),
				byte_patches: [edit, { ...edit, offset: 32769 }],
			}),
		),
	).rejects.toThrow("aggregate");
	await expect(
		advancedCandidate(
			request("preview_binary_patch", {
				expected_sha256: candidateHash(bytes),
				byte_patches: Array.from({ length: 33 }, (_, offset) => ({
					offset,
					expected_hex: "00",
					replacement_hex: "ff",
				})),
			}),
		),
	).rejects.toThrow();
});
it("enforces aggregate multi-literal character budget", async () => {
	target = join(root, "owned.ts");
	output = join(root, "candidate.ts");
	const literal = JSON.stringify("x".repeat(40000)),
		source = `const a = ${literal}; const b = ${literal};`;
	await writeFile(target, source);
	await expect(
		advancedCandidate(
			request("preview_ast_transform", {
				expected_sha256: candidateHash(Buffer.from(source)),
				literals: [
					{
						start: source.indexOf(literal),
						expected: literal,
						replacement: '"a"',
					},
					{
						start: source.lastIndexOf(literal),
						expected: literal,
						replacement: '"b"',
					},
				],
			}),
		),
	).rejects.toThrow("aggregate");
});
