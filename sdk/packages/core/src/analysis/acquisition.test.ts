import {
	mkdtemp,
	mkdir,
	writeFile,
	readFile,
	rm,
	realpath,
	symlink,
} from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { randomUUID } from "node:crypto";
import { beforeEach, afterEach, expect, it } from "vitest";
import { AcquisitionSchema, acquisitionDigest } from "./acquisition";
import { analyzeTarget, readSources } from "./worker";
import {
	byteDigest,
	digest,
	ResultSchema,
	ANALYSIS_PROFILE,
} from "./contracts";
import { runFirstPartyAnalysis } from "./service";
import { FirstPartyAnalysisStore, queryFirstPartyEvidence } from "./index";

let root: string;
beforeEach(async () => {
	root = await realpath(await mkdtemp(join(tmpdir(), "cline-acquisition-")));
});
afterEach(async () => {
	await rm(root, { recursive: true, force: true });
});
function archive(files: Record<string, unknown>, data: Buffer) {
	const json = Buffer.from(JSON.stringify({ files }));
	const padding = (4 - (json.length % 4)) % 4;
	const header = Buffer.alloc(16 + json.length + padding);
	header.writeUInt32LE(4, 0);
	header.writeUInt32LE(header.length - 8, 4);
	header.writeUInt32LE(header.length - 12, 8);
	header.writeUInt32LE(json.length, 12);
	json.copy(header, 16);
	return Buffer.concat([header, data]);
}
it("binds actual ASAR container bytes and exact source ranges without executing source", async () => {
	const data = Buffer.from('throw new Error("MUST_NOT_EXECUTE");');
	const bytes = archive(
		{ "main.js": { offset: "0", size: data.length } },
		data,
	);
	await writeFile(join(root, "APP.ASAR"), bytes);
	const result = await analyzeTarget(root, { target: "APP.ASAR" });
	const report = result.acquisition!;
	expect(report.coverage).toBe("partial");
	expect(report.containers).toEqual([
		{
			path: "APP.ASAR",
			sha256: byteDigest(bytes),
			bytes: bytes.length,
			kind: "asar-candidate",
		},
	]);
	const source = report.sources[0]!;
	expect(source.origin).toEqual({
		kind: "asar-member",
		containerPath: "APP.ASAR",
		containerSha256: byteDigest(bytes),
		offset: bytes.length - data.length,
	});
	expect(source.sha256).toBe(byteDigest(data));
	expect(bytes.subarray((source.origin as { offset: number }).offset)).toEqual(
		data,
	);
	expect(await readFile(join(root, "APP.ASAR"))).toEqual(bytes);
	expect(report.limitations.join(" ")).toContain("not publisher authenticity");
});
it("directory snapshots retain separate file origins and exclude dependencies explicitly", async () => {
	await mkdir(join(root, "node_modules"));
	await writeFile(join(root, "node_modules", "hidden.js"), "throw 1");
	await writeFile(join(root, "main.js"), "export const x=1;");
	const a = await analyzeTarget(root, { target: "." });
	const b = await analyzeTarget(root, { target: "." });
	expect(a.acquisition).toEqual(b.acquisition);
	expect(a.acquisition?.sources[0]?.origin).toEqual({
		kind: "file",
		path: "main.js",
	});
	expect(a.acquisition?.selectedPath).toBe(".");
	expect(a.acquisition?.limitations.join(" ")).toContain(
		"Excluded node_modules",
	);
	expect(a.acquisition?.limitations.join(" ")).toContain(
		"not an atomic filesystem snapshot",
	);
});
it("does not admit earlier archive members if a later selected range is malformed", async () => {
	await writeFile(
		join(root, "bad.asar"),
		archive(
			{
				"first.js": { offset: "0", size: 1 },
				"second.js": { offset: "500", size: 10 },
			},
			Buffer.from("x"),
		),
	);
	const result = await analyzeTarget(root, { target: "bad.asar" });
	expect(result.artifacts).toEqual([]);
	expect(result.acquisition?.sources).toEqual([]);
	expect(result.acquisition?.containers).toHaveLength(1);
	expect(result.status).toBe("partial");
	expect(result.acquisition?.limitations.join(" ")).toContain(
		"Invalid ASAR source range",
	);
});
it("unpacked and linked members remain unknown and are never followed", async () => {
	await writeFile(
		join(root, "owned.asar"),
		archive(
			{
				"unpacked.js": { unpacked: true, size: 1 },
				"linked.js": { link: "../outside.js" },
				"ok.js": { offset: "0", size: 1 },
			},
			Buffer.from("x"),
		),
	);
	const result = await analyzeTarget(root, { target: "owned.asar" });
	expect(result.acquisition?.sources.map((s) => s.path)).toEqual([
		"owned.asar!/ok.js",
	]);
	expect(result.acquisition?.limitations.join(" ")).toContain(
		"linked/unpacked",
	);
});
it("rejects altered manifest identities, container ranges, duplicate paths and artifact projections", async () => {
	await writeFile(
		join(root, "owned.asar"),
		archive({ "a.js": { offset: "0", size: 1 } }, Buffer.from("x")),
	);
	const result = await analyzeTarget(root, { target: "owned.asar" });
	const original = result.acquisition!;
	const unsafePath = structuredClone(original);
	unsafePath.sources[0]!.path = "../outside.js";
	expect(AcquisitionSchema.safeParse(unsafePath).success).toBe(false);
	expect(
		AcquisitionSchema.safeParse({ ...original, manifestSha256: "0".repeat(64) })
			.success,
	).toBe(false);
	for (const mutate of [
		(r: typeof original) => {
			r.sources[0]!.path = "../escape.js";
		},
		(r: typeof original) => {
			r.sources.push(r.sources[0]!);
		},
		(r: typeof original) => {
			r.containers[0]!.sha256 = "0".repeat(64);
		},
		(r: typeof original) => {
			(r.sources[0]!.origin as { offset: number }).offset = 1_000_000;
		},
	]) {
		const r = structuredClone(original);
		mutate(r);
		let valid = false;
		try {
			const { manifestSha256: _hash, ...body } = r;
			r.manifestSha256 = acquisitionDigest(body);
			valid = AcquisitionSchema.safeParse(r).success;
		} catch {}
		expect(valid).toBe(false);
	}
	const changed = structuredClone(result);
	changed.artifacts[0]!.sha256 = "0".repeat(64);
	expect(ResultSchema.safeParse(changed).success).toBe(false);
});
it("saved acquisition is paginated, hash-bound, readable while Off and session-owned", async () => {
	await writeFile(join(root, "a.js"), "export const a=1;");
	await writeFile(join(root, "b.js"), "export const b=2;");
	const result = await analyzeTarget(root, { target: "." });
	const store = new FirstPartyAnalysisStore(join(root, "ledger.sqlite"));
	try {
		store.setMode("owner", root, "static");
		const id = randomUUID();
		const receipt = {
			id,
			sessionId: "owner",
			workspace: root,
			status: "running" as const,
			profile: ANALYSIS_PROFILE,
			input: { target: "." },
			requestHash: digest({ id }),
			createdAt: new Date().toISOString(),
		};
		store.start(receipt);
		store.save({
			...receipt,
			status: result.status,
			result,
			resultHash: digest(result),
		});
		store.setMode("owner", root, "off");
		const page = queryFirstPartyEvidence(
			"owner",
			{ receiptId: id, view: "source-acquisition", limit: 1 },
			store,
		);
		expect(page).toMatchObject({
			available: true,
			providerCalls: 0,
			targetExecuted: false,
			verifiedBehavior: false,
			total: 2,
			nextOffset: 1,
			manifestSha256: result.acquisition!.manifestSha256,
		});
		expect(() =>
			queryFirstPartyEvidence(
				"other",
				{ receiptId: id, view: "source-acquisition" },
				store,
			),
		).toThrow();
		expect(
			queryFirstPartyEvidence(
				"owner",
				{ receiptId: id, view: "source-containers" },
				store,
			),
		).toMatchObject({ total: 0 });
	} finally {
		store.close();
	}
});
it("does not hash unsupported files or follow filesystem links", async () => {
	await writeFile(join(root, "opaque.bin"), "unselected");
	const unsupported = await readSources(root, "opaque.bin");
	expect(unsupported.acquisition.sources).toEqual([]);
	expect(unsupported.acquisition.containers).toEqual([]);
	if (process.platform !== "win32") {
		await symlink(join(root, "opaque.bin"), join(root, "linked.js"));
		const selected = await readSources(root, ".");
		expect(selected.acquisition.sources).toEqual([]);
		expect(selected.acquisition.limitations.join(" ")).toContain(
			"filesystem link",
		);
	}
});
it("caps aggregate archive reads without increasing the per-file or source budgets", async () => {
	const bytes = archive(
		{ "a.js": { offset: "0", size: 1 } },
		Buffer.alloc(24 * 1024 * 1024),
	);
	for (const name of ["a.asar", "b.asar", "c.asar"])
		await writeFile(join(root, name), bytes);
	const result = await analyzeTarget(root, { target: "." });
	expect(result.acquisition?.containers).toHaveLength(2);
	expect(result.acquisition?.sources).toHaveLength(2);
	expect(
		result.acquisition?.containers.reduce((n, c) => n + c.bytes, 0),
	).toBeLessThanOrEqual(64 * 1024 * 1024);
	expect(result.status).toBe("partial");
	expect(result.limitations.join(" ")).toContain("byte budget");
});
it("parent rejects a child acquisition bound to another selected target", async () => {
	await writeFile(join(root, "a.js"), "export const a=1;");
	const result = await analyzeTarget(root, { target: "a.js" });
	result.acquisition!.selectedPath = "other.js";
	const { manifestSha256: _hash, ...body } = result.acquisition!;
	result.acquisition!.manifestSha256 = acquisitionDigest(body);
	const script = join(root, "owned-child.mjs");
	await writeFile(
		script,
		`process.stdin.resume();process.stdin.on("end",()=>process.stdout.write(${JSON.stringify(JSON.stringify(result))}));`,
	);
	const store = new FirstPartyAnalysisStore(join(root, "parent.sqlite"));
	try {
		store.setMode("owner", root, "static");
		const r = await runFirstPartyAnalysis(
			"owner",
			{ target: "a.js" },
			undefined,
			store,
			JSON.stringify({ executable: process.execPath, args: [script] }),
		);
		expect(r.status).toBe("failed");
		expect(r.result).toBeUndefined();
	} finally {
		store.close();
	}
});

it("shares aggregate archive admission across compared source sets", async () => {
	const bytes = archive(
		{ "a.js": { offset: "0", size: 1 } },
		Buffer.alloc(24 * 1024 * 1024),
	);
	for (const name of ["a.asar", "b.asar", "c.asar"])
		await writeFile(join(root, name), bytes);
	const budget = { entries: 0, bytes: 0, files: 0 };
	await readSources(root, "a.asar", budget);
	await readSources(root, "b.asar", budget);
	const c = await readSources(root, "c.asar", budget);
	expect(c.acquisition.containers).toEqual([]);
	expect(c.sources).toEqual([]);
	expect(c.limitations.join(" ")).toContain("byte budget");
});
it("rejects inconsistent pickle lengths, non-UTF8 headers and control-character member labels atomically", async () => {
	const valid = archive({ "a.js": { offset: "0", size: 1 } }, Buffer.from("x"));
	const wrongPickle = Buffer.from(valid);
	wrongPickle.writeUInt32LE(0, 8);
	const invalidUtf8 = Buffer.from(valid);
	invalidUtf8[16 + invalidUtf8.subarray(16).indexOf(Buffer.from("a.js"))] = 255;
	const control = archive(
		{ "bad\n.js": { offset: "0", size: 1 } },
		Buffer.from("x"),
	);
	for (const [i, bytes] of [wrongPickle, invalidUtf8, control].entries()) {
		await writeFile(join(root, `${i}.asar`), bytes);
		const r = await analyzeTarget(root, { target: `${i}.asar` });
		expect(r.status).toBe("partial");
		expect(r.artifacts).toEqual([]);
		expect(r.acquisition?.sources).toEqual([]);
	}
});
it.skipIf(process.platform === "win32")(
	"skips unsupported filesystem path labels without losing valid sources",
	async () => {
		await writeFile(join(root, "bad\\name.js"), "throw 1");
		await writeFile(join(root, "bad\nname.js"), "throw 1");
		await writeFile(join(root, "good.js"), "export const a=1;");
		const r = await analyzeTarget(root, { target: "." });
		expect(r.artifacts.map((a) => a.path)).toEqual(["good.js"]);
		expect(r.acquisition?.limitations.join(" ")).toContain(
			"unsupported acquisition path label",
		);
	},
);
