import { createHash } from "node:crypto";
import {
	mkdir,
	mkdtemp,
	readFile,
	realpath,
	rename,
	rm,
	symlink,
	writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, expect, it } from "vitest";
import { NativeProjectEditSchema } from "../native-project-edits-schema";
import {
	NATIVE_GHIDRA_EDIT_SCRIPT,
	nativeIdaEditScript,
} from "./native-project-edit-scripts";
import {
	runNativeProjectCandidate,
	assertNativeManifestBudget,
	type CandidateOptions,
	type EditEngineRequest,
} from "./native-project-candidates";
const hash = (s: string) => createHash("sha256").update(s).digest("hex");
const roots: string[] = [];
afterEach(async () => {
	for (const p of roots.splice(0))
		await rm(p, { recursive: true, force: true });
});
const original = {
	name: "fixture_main",
	comment: "",
	prototype: "int fixture_main(void)",
};
async function fixture(engine: "ida" | "ghidra" = "ida") {
	const root = await realpath(
		await mkdtemp(join(tmpdir(), "native-candidate-owned-")),
	);
	roots.push(root);
	const source = join(root, "original.bin");
	await writeFile(source, "owned fixture");
	const state = {
			wrongReceipt: false,
			failAfterSave: false,
			wrongPersisted: false,
			cancelAfterSave: undefined as AbortController | undefined,
		},
		calls: EditEngineRequest[] = [];
	const base: Omit<CandidateOptions, "edit"> = {
		root: join(root, "candidates"),
		engine,
		artifactSha256: hash("owned fixture"),
		engineSha256: hash("owned fixture engine"),
		leaseRoot: join(root, "leases"),
		selector: { address: "0x10" },
		prepareInput: async (stage) => {
			await writeFile(join(stage, "input.bin"), await readFile(source));
		},
		verifyTarget: async () => {
			if (hash((await readFile(source)).toString()) !== hash("owned fixture"))
				throw new Error("Target changed");
		},
		run: async (stage, r) => {
			calls.push(r);
			const file = join(
				stage,
				engine === "ida" ? "candidate.i64" : "candidate.rep/state.json",
			);
			let before = { ...original };
			try {
				before = JSON.parse(await readFile(file, "utf8"));
			} catch (e) {
				if ((e as NodeJS.ErrnoException).code !== "ENOENT") throw e;
			}
			if (r.expected && JSON.stringify(before) !== JSON.stringify(r.expected))
				throw new Error("Fixture native before-state changed");
			let after = { ...before };
			if (r.mode === "candidate") {
				if (r.changes?.prototype?.includes("INVALID"))
					throw new Error("Fixture prototype parser rejected declaration");
				after = { ...after, ...r.changes };
			}
			await mkdir(join(stage, "candidate.rep"), { recursive: true });
			await writeFile(file, JSON.stringify(after));
			if (engine === "ghidra")
				await writeFile(
					join(stage, "candidate.gpr"),
					"owned Ghidra protocol fixture, not a Ghidra project",
				);
			if (r.mode === "candidate" && state.failAfterSave)
				throw new Error("Fixture failed after isolated save");
			if (r.mode === "candidate") state.cancelAfterSave?.abort();
			if (r.mode === "verify" && state.wrongPersisted)
				after.comment = "wrong persisted field";
			return {
				requestId: state.wrongReceipt ? "wrong" : r.requestId,
				requestHash: r.requestHash,
				entry: "0x10",
				before,
				after,
				status:
					r.mode === "preview"
						? "preview"
						: r.mode === "candidate"
							? "candidate-ready"
							: "verified",
			};
		},
	};
	const run = (
		edit: CandidateOptions["edit"],
		extra: Partial<CandidateOptions> = {},
	) => runNativeProjectCandidate({ ...base, edit, ...extra });
	const head = async () => {
		try {
			return JSON.parse(await readFile(join(base.root, "HEAD.json"), "utf8"))
				.manifestSha256;
		} catch (e) {
			if ((e as NodeJS.ErrnoException).code === "ENOENT") return null;
			throw e;
		}
	};
	return { root, source, base, state, calls, run, head };
}
const candidate = (before = original, head: string | null = null) => ({
	mode: "candidate" as const,
	expected_state: before,
	expected_head_sha256: head,
	changes: {
		comment: "reviewed note",
		prototype: "long fixture_main(int value)",
	},
	confirm_candidate_write: true,
});
it.each([
	"ida",
	"ghidra",
] as const)("previews and publishes a separately reopened isolated %s candidate without changing source", async (engine) => {
	const f = await fixture(engine),
		preview = await f.run({ mode: "preview" });
	expect(preview.status).toBe("preview");
	expect(await f.head()).toBe(null);
	const result = await f.run(candidate());
	if (result.status !== "candidate-published")
		throw new Error("Expected published fixture candidate");
	expect(result.status).toBe("candidate-published");
	expect(await f.head()).toBe(result.headSha256);
	expect(f.calls.map((r) => r.mode)).toEqual([
		"preview",
		"candidate",
		"verify",
	]);
	expect(await readFile(f.source, "utf8")).toBe("owned fixture");
	expect(result.rollbackContract).toBe(
		engine === "ghidra"
			? "native-transaction-plus-isolated-candidate"
			: "isolated-candidate-no-native-undo-claim",
	);
});
it("retains immutable prior candidates and rolls back only the reviewed active pointer", async () => {
	const f = await fixture(),
		first = await f.run(candidate());
	if (first.status !== "candidate-published")
		throw new Error("Expected published fixture candidate");
	const before = { ...original, ...candidate().changes };
	const second = await f.run({
		...candidate(before, first.headSha256!),
		changes: { name: "reviewed_main", comment: "second" },
	});
	const saved = await readFile(first.projectPath!, "utf8");
	const calls = f.calls.length;
	const rolled = await f.run({
		mode: "rollback",
		expected_head_sha256: second.headSha256!,
		confirm_pointer_rollback: true,
	});
	expect(rolled.pointerOnly).toBe(true);
	expect(await f.head()).toBe(first.headSha256);
	expect(f.calls.length).toBe(calls);
	expect(await readFile(first.projectPath!, "utf8")).toBe(saved);
	const cleared = await f.run({
		mode: "rollback",
		expected_head_sha256: first.headSha256!,
		confirm_pointer_rollback: true,
	});
	expect(cleared.headSha256).toBe(null);
	expect(await f.head()).toBe(null);
});
it("rejects stale head or exact function before-state before publication", async () => {
	const f = await fixture(),
		first = await f.run(candidate());
	if (first.status !== "candidate-published")
		throw new Error("Expected published fixture candidate");
	const count = f.calls.length;
	await expect(f.run(candidate())).rejects.toThrow("head changed");
	expect(f.calls.length).toBe(count);
	await expect(f.run(candidate(original, first.headSha256!))).rejects.toThrow(
		"before-state changed",
	);
	expect(await f.head()).toBe(first.headSha256);
});
it.each([
	"wrongReceipt",
	"failAfterSave",
	"wrongPersisted",
] as const)("keeps failed %s candidate unpublished", async (key) => {
	const f = await fixture();
	f.state[key] = true;
	await expect(f.run(candidate())).rejects.toThrow();
	expect(await f.head()).toBe(null);
	expect(await readFile(f.source, "utf8")).toBe("owned fixture");
});
it("does not publish cancellation after a private candidate save", async () => {
	const f = await fixture(),
		controller = new AbortController();
	f.state.cancelAfterSave = controller;
	await expect(
		f.run(candidate(), { signal: controller.signal }),
	).rejects.toThrow();
	expect(await f.head()).toBe(null);
	expect(f.calls.map((r) => r.mode)).toEqual(["candidate"]);
});
it("rejects changed project bytes instead of cloning or rolling back a corrupted candidate", async () => {
	const f = await fixture(),
		result = await f.run(candidate());
	if (result.status !== "candidate-published")
		throw new Error("Expected published fixture candidate");
	await writeFile(result.projectPath!, "tampered project");
	await expect(f.run({ mode: "preview" })).rejects.toThrow(
		"project integrity mismatch",
	);
	await expect(
		f.run({
			mode: "rollback",
			expected_head_sha256: result.headSha256!,
			confirm_pointer_rollback: true,
		}),
	).rejects.toThrow("project integrity mismatch");
	expect(await f.head()).toBe(result.headSha256);
});
it("rejects redirected candidate project directories even with identical bytes", async () => {
	const f = await fixture("ghidra"),
		result = await f.run(candidate());
	if (result.status !== "candidate-published")
		throw new Error("Expected published fixture candidate");
	const project = join(
			result.projectPath!.replace(/candidate\.gpr$/, ""),
			"candidate.rep",
		),
		moved = join(f.root, "moved");
	await rename(project, moved);
	await symlink(moved, project, "junction");
	await expect(f.run({ mode: "preview" })).rejects.toThrow(
		"links not permitted",
	);
});
it("requires explicit write/rollback acknowledgement, exact expected head and single data-only declaration", () => {
	for (const edit of [
		{ mode: "candidate", changes: { name: "x" } },
		{
			mode: "rollback",
			expected_head_sha256: null,
			confirm_pointer_rollback: true,
		},
		{ mode: "preview", changes: { comment: "x" } },
		{ ...candidate(), changes: { prototype: "int x(); int y();" } },
		{ ...candidate(), changes: { name: 'x";code' } },
	])
		expect(NativeProjectEditSchema.safeParse(edit).success).toBe(false);
	expect(NativeProjectEditSchema.safeParse(candidate()).success).toBe(true);
});
it("fixed adapters distinguish Ghidra native rollback from isolated IDA candidates", () => {
	expect(NATIVE_GHIDRA_EDIT_SCRIPT).toContain("startTransaction");
	expect(NATIVE_GHIDRA_EDIT_SCRIPT).toContain("endTransaction(tx,commit)");
	expect(NATIVE_GHIDRA_EDIT_SCRIPT).toContain(
		"Persisted candidate state mismatch",
	);
	expect(NATIVE_GHIDRA_EDIT_SCRIPT).toContain("signature.getArguments()");
	const ida = nativeIdaEditScript('C:\\owned"; #', "receipt", "candidate.i64");
	expect(
		JSON.parse(
			ida
				.split("\n")
				.find((x) => x.startsWith("REQUEST="))!
				.slice(8),
		),
	).toBe('C:\\owned"; #');
	expect(ida).toContain("actual.equals_to(tif)");
	expect(ida).toContain("save_database(DATABASE,0)");
	expect(ida).not.toContain("eval(");
	expect(ida).not.toContain("exec(");
});

it.each([
	"candidate",
	"rollback",
] as const)("rejects %s cancellation during final identity verification before pointer commit", async (mode) => {
	const f = await fixture();
	let expectedHead: string | null = null;
	if (mode === "rollback") {
		const published = await f.run(candidate());
		expectedHead = published.headSha256;
	}
	const controller = new AbortController();
	let reads = 0;
	const edit =
		mode === "candidate"
			? candidate()
			: {
					mode: "rollback" as const,
					expected_head_sha256: expectedHead!,
					confirm_pointer_rollback: true,
				};
	await expect(
		f.run(edit, {
			signal: controller.signal,
			verifyTarget: async () => {
				await f.base.verifyTarget();
				if (++reads === 2) controller.abort();
			},
		}),
	).rejects.toThrow();
	expect(await f.head()).toBe(expectedHead);
});
it("rejects oversized manifest metadata before publication, including UTF-8 byte expansion", () => {
	expect(() =>
		assertNativeManifestBudget("x".repeat(1024 * 1024)),
	).not.toThrow();
	expect(() => assertNativeManifestBudget("x".repeat(1024 * 1024 + 1))).toThrow(
		"pointer unchanged",
	);
	expect(() => assertNativeManifestBudget("€".repeat(400000))).toThrow(
		"byte budget exceeded",
	);
});
