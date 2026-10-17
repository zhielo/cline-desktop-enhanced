import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, expect, it, vi } from "vitest";
import {
	analysisCommandCatalog,
	isAnalysisWriteOperation,
} from "../analysis-commands";
import { ReverseEngineeringInputSchema } from "../schemas";
import { androidProjectCandidate } from "./android-project-candidate";
import { scanAndroidProject } from "./android-project-files";
import { candidateHash } from "./candidate-files";
import type { InvestigationRunner } from "./investigation-workflows";

vi.mock("node:fs/promises", async (importOriginal) => {
	const actual = await importOriginal<typeof import("node:fs/promises")>();
	return { ...actual, rm: vi.fn(actual.rm) };
});

const dirs: string[] = [];
afterEach(async () => {
	await Promise.all(
		dirs.splice(0).map((d) => fs.rm(d, { recursive: true, force: true })),
	);
});
const before =
	".method public static value()I\n .registers 1\n const/4 v0, 0x0\n return v0\n.end method";
const after = before.replace("0x0", "0x1");
async function fixture() {
	const dir = await fs.realpath(
		await fs.mkdtemp(path.join(os.tmpdir(), "cline-project-test-")),
	);
	dirs.push(dir);
	const target = path.join(dir, "project");
	await fs.mkdir(target);
	const text = `.class public Lowned/Sample;\n.super Ljava/lang/Object;\n${before}\n`;
	for (const root of ["smali", "smali_classes2"]) {
		await fs.mkdir(path.join(target, root));
		await fs.writeFile(path.join(target, root, "Sample.smali"), text);
	}
	await fs.writeFile(path.join(target, "AndroidManifest.xml"), "<manifest/>");
	await fs.writeFile(path.join(target, "apktool.yml"), "version: 3.0.3\n");
	const input = ReverseEngineeringInputSchema.parse({
		operation: "preview_android_candidate",
		target,
		output_file: path.join(dir, "candidate.apk"),
		android_project_patch: {
			patches: [
				{
					path: "smali/Sample.smali",
					patch: {
						expected_sha256: candidateHash(text),
						class_descriptor: "Lowned/Sample;",
						method_signature: "value()I",
						expected_method: before,
						replacement_method: after,
					},
				},
			],
		},
	});
	const run = vi.fn<InvestigationRunner>(async (request) => {
		if (request.operation === "assemble_smali")
			return {
				succeeded: true,
				outputSha256: "a".repeat(64),
				outputValidation: "bounded-structure-checked; mock unit engine",
			};
		const bytes = Buffer.from("unit fixture, not an actual APK");
		await fs.writeFile(request.output_file!, bytes);
		return {
			succeeded: true,
			outputSha256: candidateHash(bytes),
			outputValidation: "bounded-structure-checked; mock unit engine",
		};
	});
	const preview = await androidProjectCandidate(input, run);
	const build = ReverseEngineeringInputSchema.parse({
		...input,
		operation: "build_android_candidate",
		android_project_patch: {
			...input.android_project_patch,
			expected_project_sha256: preview.projectSha256,
			preview_sha256: preview.previewSha256,
		},
	});
	return { dir, target, text, input, run, preview, build };
}
it("advertises project preview and preserves Modify classification", () => {
	expect(
		analysisCommandCatalog().entries.filter(
			(e) => e.command === "preview_android_candidate",
		),
	).toHaveLength(1);
	expect(isAnalysisWriteOperation("preview_android_candidate")).toBe(false);
	expect(isAnalysisWriteOperation("build_android_candidate")).toBe(true);
});
it("previews exact differences without invoking engines or publishing", async () => {
	const f = await fixture();
	expect(f.run).not.toHaveBeenCalled();
	expect(f.preview.published).toBe(false);
	expect(f.preview.observedExecution).toBe(false);
	expect(f.preview).toMatchObject({
		status: "completed",
		effect: "plan-only",
		engineReadiness: "not-probed",
		diffs: [{ path: "smali/Sample.smali", diff: { before, after } }],
	});
	await expect(fs.stat(f.input.output_file!)).rejects.toMatchObject({
		code: "ENOENT",
	});
});
it("snapshots, patches, assembles every root and reuses the existing builder before publishing", async () => {
	const f = await fixture();
	const initial = await scanAndroidProject(f.target);
	const result = await androidProjectCandidate(f.build, f.run);
	expect(result).toMatchObject({
		status: "completed",
		published: true,
		sourceUnchanged: true,
		observedExecution: false,
		signingStatus: "new-unsigned-artifact",
	});
	expect(result.stages.map((s) => s.id)).toEqual([
		"patch-0",
		"assemble-smali",
		"assemble-smali_classes2",
		"rebuild-apk",
	]);
	expect((await scanAndroidProject(f.target)).sha256).toBe(initial.sha256);
	expect(
		await fs.readFile(path.join(f.target, "smali/Sample.smali"), "utf8"),
	).toBe(f.text);
	expect(await fs.readFile(f.input.output_file!, "utf8")).toBe(
		"unit fixture, not an actual APK",
	);
	const temporary = f.run.mock.calls[0][0].target!;
	await expect(fs.stat(temporary)).rejects.toMatchObject({ code: "ENOENT" });
});
it.each([
	"../escape.smali",
	"smali/../escape.smali",
	"smali\\x.smali",
	"smali/x:stream.smali",
	"/smali/a.smali",
	"smali_classes01/a.smali",
])("rejects unconfined/ambiguous patch path %s", async (value) => {
	const f = await fixture();
	const input = {
		...f.input,
		android_project_patch: {
			...f.input.android_project_patch!,
			patches: [{ ...f.input.android_project_patch!.patches[0], path: value }],
		},
	};
	await expect(androidProjectCandidate(input, f.run)).rejects.toThrow(
		"confined",
	);
	expect(f.run).not.toHaveBeenCalled();
});
it("rejects duplicate/case-alias patch files", async () => {
	const f = await fixture(),
		p = f.input.android_project_patch!.patches[0];
	await expect(
		androidProjectCandidate(
			{
				...f.input,
				android_project_patch: {
					patches: [
						p,
						{
							...p,
							path: p.path
								.toUpperCase()
								.replace("SMALI/", "smali/")
								.replace(".SMALI", ".smali"),
						},
					],
				},
			},
			f.run,
		),
	).rejects.toThrow("unique");
});
it("requires both whole-project hash and exact preview for build", async () => {
	const f = await fixture();
	for (const config of [
		{ patches: f.build.android_project_patch!.patches },
		{ ...f.build.android_project_patch!, preview_sha256: "f".repeat(64) },
		{
			...f.build.android_project_patch!,
			expected_project_sha256: "f".repeat(64),
		},
	])
		await expect(
			androidProjectCandidate(
				{ ...f.build, android_project_patch: config },
				f.run,
			),
		).rejects.toThrow(/fingerprint|preview/);
	expect(f.run).not.toHaveBeenCalled();
});
it("rejects a resource change, not just changes to selected Smali files", async () => {
	const f = await fixture();
	await fs.writeFile(path.join(f.target, "new-resource.txt"), "changed");
	await expect(androidProjectCandidate(f.build, f.run)).rejects.toThrow(
		"fingerprint",
	);
	expect(f.run).not.toHaveBeenCalled();
});
it("binds destination and API level to preview", async () => {
	const f = await fixture();
	for (const edit of [
		{ output_file: path.join(f.dir, "other.apk") },
		{ smali_api_level: 28 },
	])
		await expect(
			androidProjectCandidate({ ...f.build, ...edit }, f.run),
		).rejects.toThrow("preview_sha256");
	expect(f.run).not.toHaveBeenCalled();
});
it("rejects a destination inside the original project", async () => {
	const f = await fixture();
	await expect(
		androidProjectCandidate(
			{ ...f.input, output_file: path.join(f.target, "inside.apk") },
			f.run,
		),
	).rejects.toThrow("outside");
});
it("stops before rebuild when a Smali root fails", async () => {
	const f = await fixture();
	f.run.mockResolvedValue({
		succeeded: false,
		exitCode: 1,
		stderr: "owned diagnostic",
	});
	const r = await androidProjectCandidate(f.build, f.run);
	expect(r.status).toBe("blocked");
	expect(r.published).toBe(false);
	expect(f.run).toHaveBeenCalledTimes(1);
	await expect(fs.stat(f.build.output_file!)).rejects.toMatchObject({
		code: "ENOENT",
	});
});
it("stops on thrown engine error with bounded failed stage evidence", async () => {
	const f = await fixture();
	f.run.mockRejectedValue(new Error("sensitive untrusted output"));
	const r = await androidProjectCandidate(f.build, f.run);
	expect(r.status).toBe("blocked");
	expect(r.stages[1].result).toMatchObject({
		status: "failed",
		succeeded: false,
	});
	expect(JSON.stringify(r)).not.toContain("sensitive untrusted output");
});
it("does not publish when the existing builder fails", async () => {
	const f = await fixture();
	f.run.mockImplementation(async (request) => ({
		succeeded: request.operation === "assemble_smali",
	}));
	const r = await androidProjectCandidate(f.build, f.run);
	expect(r.published).toBe(false);
	expect(r.status).toBe("blocked");
	expect(f.run).toHaveBeenCalledTimes(3);
});
it("rejects builder hash mismatches", async () => {
	const f = await fixture();
	f.run.mockImplementation(async (request) => {
		if (request.operation === "assemble_smali") return { succeeded: true };
		await fs.writeFile(request.output_file!, "tampered");
		return {
			succeeded: true,
			outputSha256: "b".repeat(64),
			outputValidation: "bounded-structure-checked",
		};
	});
	await expect(androidProjectCandidate(f.build, f.run)).rejects.toThrow("hash");
	await expect(fs.stat(f.build.output_file!)).rejects.toMatchObject({
		code: "ENOENT",
	});
});
it("rejects a changed original before publication", async () => {
	const f = await fixture();
	const original = f.run.getMockImplementation()!;
	f.run.mockImplementation(async (req, signal) => {
		const r = await original(req, signal);
		if (req.operation === "rebuild_apk")
			await fs.writeFile(path.join(f.target, "AndroidManifest.xml"), "changed");
		return r;
	});
	await expect(androidProjectCandidate(f.build, f.run)).rejects.toThrow(
		"Original project changed",
	);
	await expect(fs.stat(f.build.output_file!)).rejects.toMatchObject({
		code: "ENOENT",
	});
});
it("rejects extra candidate changes outside the approved patch", async () => {
	const f = await fixture();
	const original = f.run.getMockImplementation()!;
	f.run.mockImplementation(async (req, signal) => {
		const r = await original(req, signal);
		if (req.operation === "rebuild_apk")
			await fs.writeFile(
				path.join(req.target!, "AndroidManifest.xml"),
				"changed",
			);
		return r;
	});
	await expect(androidProjectCandidate(f.build, f.run)).rejects.toThrow(
		"outside the approved",
	);
});
it("never overwrites a destination created during the build", async () => {
	const f = await fixture();
	const original = f.run.getMockImplementation()!;
	f.run.mockImplementation(async (req, signal) => {
		const r = await original(req, signal);
		if (req.operation === "rebuild_apk")
			await fs.writeFile(f.build.output_file!, "preexisting");
		return r;
	});
	await expect(androidProjectCandidate(f.build, f.run)).rejects.toThrow(
		"exists",
	);
	expect(await fs.readFile(f.build.output_file!, "utf8")).toBe("preexisting");
});
it("honors cancellation before engine invocation", async () => {
	const f = await fixture(),
		control = new AbortController();
	control.abort();
	await expect(
		androidProjectCandidate(f.build, f.run, control.signal),
	).rejects.toThrow();
	expect(f.run).not.toHaveBeenCalled();
});
it("retains private input when engine termination is unconfirmed", async () => {
	const f = await fixture();
	f.run.mockResolvedValue({ succeeded: false, outputDrainTimedOut: true });
	const r = await androidProjectCandidate(f.build, f.run);
	expect(r.cleanup).toBe("deferred-unconfirmed-engine-termination");
	const temporary = f.run.mock.calls[0][0].target!;
	expect((await fs.stat(temporary)).isDirectory()).toBe(true);
	dirs.push(path.dirname(path.dirname(temporary)));
	expect(r.published).toBe(false);
});
it("rejects linked project entries and fingerprints unchanged snapshots identically", async () => {
	const f = await fixture(),
		copy = path.join(f.dir, "copy");
	const a = await scanAndroidProject(f.target, { copyTo: copy });
	expect((await scanAndroidProject(copy)).sha256).toBe(a.sha256);
	if (process.platform !== "win32") {
		await fs.symlink(
			path.join(f.target, "AndroidManifest.xml"),
			path.join(f.target, "linked.xml"),
		);
		await expect(scanAndroidProject(f.target)).rejects.toThrow("Symbolic");
	}
});

it("preserves a published receipt if private workspace cleanup fails", async () => {
	const f = await fixture(),
		remove = vi.mocked(fs.rm).getMockImplementation()!;
	const spy = vi.mocked(fs.rm).mockImplementation(async (file, options) => {
		if (String(file).includes("cline-android-candidate-") && options?.recursive)
			throw new Error("owned cleanup failure");
		return remove(file, options);
	});
	try {
		const result = await androidProjectCandidate(f.build, f.run);
		expect(result.published).toBe(true);
		expect(result.status).toBe("completed");
		expect(result.cleanupWarnings).toHaveLength(1);
		expect(await fs.readFile(f.build.output_file!, "utf8")).toContain(
			"unit fixture",
		);
		dirs.push(path.dirname(path.dirname(f.run.mock.calls[0][0].target!)));
	} finally {
		spy.mockRestore();
	}
});
