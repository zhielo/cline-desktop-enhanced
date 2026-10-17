import { createHash } from "node:crypto";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { smaliPatch } from "./smali-patch";
const hash = (text: string | Buffer) =>
	createHash("sha256").update(text).digest("hex");
const before =
	".method public value()I\n    .locals 1\n    const/4 v0, 0x0\n    return v0\n.end method";
const after = before.replace("0x0", "0x1");
const original = `.class public Lowned/Sample;\n.super Ljava/lang/Object;\n\n${before}\n`;
let root: string;
let source: string;
let output: string;
beforeEach(async () => {
	root = await fs.mkdtemp(path.join(os.tmpdir(), "cline-smali-patch-test-"));
	source = path.join(root, "source.smali");
	output = path.join(root, "candidate.smali");
	await fs.writeFile(source, original);
});
afterEach(async () => {
	await fs.rm(root, { recursive: true, force: true });
});
function request(
	operation = "preview_smali_patch",
	overrides: Record<string, unknown> = {},
) {
	return {
		operation,
		target: source,
		output_file: output,
		smali_patch: {
			expected_sha256: hash(original),
			class_descriptor: "Lowned/Sample;",
			method_signature: "value()I",
			expected_method: before,
			replacement_method: after,
			...overrides,
		},
	};
}
describe("exact Smali candidate patch", () => {
	it("previews without writes, then atomically publishes one candidate and preserves original", async () => {
		const preview = await smaliPatch(request());
		expect(preview.published).toBe(false);
		await expect(fs.stat(output)).rejects.toThrow();
		const result = await smaliPatch(
			request("patch_smali_method", { preview_sha256: preview.previewSha256 }),
		);
		expect(result).toMatchObject({
			published: true,
			validation: "not-run",
			outputSha256: hash(original.replace(before, after)),
		});
		expect(await fs.readFile(source, "utf8")).toBe(original);
		expect(await fs.readFile(output, "utf8")).toBe(
			original.replace(before, after),
		);
		expect((await fs.readdir(root)).sort()).toEqual([
			"candidate.smali",
			"source.smali",
		]);
	});
	it("requires an exact matching preview, including destination", async () => {
		await expect(smaliPatch(request("patch_smali_method"))).rejects.toThrow(
			"preview_sha256",
		);
		const preview = await smaliPatch(request());
		await expect(
			smaliPatch({
				...request("patch_smali_method", {
					preview_sha256: preview.previewSha256,
				}),
				output_file: path.join(root, "other.smali"),
			}),
		).rejects.toThrow("preview_sha256");
	});
	it("rejects a stale input hash", async () => {
		await fs.appendFile(source, "# changed\n");
		await expect(smaliPatch(request())).rejects.toThrow("hash changed");
	});
	it.each([
		{ class_descriptor: "Lwrong/Type;" },
		{ method_signature: "missing()V" },
		{ expected_method: before.replace("0x0", "0x2") },
		{ replacement_method: after.replace("value()I", "other()I") },
		{ replacement_method: after + "\n" + after },
		{
			replacement_method: after.replace(
				"    .locals",
				".class public Lwrong;\n    .locals",
			),
		},
		{ replacement_method: before },
	])("rejects ambiguous, mismatched and invalid replacement %j", async (overrides) => {
		await expect(
			smaliPatch(request("preview_smali_patch", overrides)),
		).rejects.toThrow();
	});
	it("rejects duplicate methods", async () => {
		const duplicate = original + before + "\n";
		await fs.writeFile(source, duplicate);
		await expect(
			smaliPatch(
				request("preview_smali_patch", { expected_sha256: hash(duplicate) }),
			),
		).rejects.toThrow("exactly one");
	});
	it("never overwrites an existing artifact", async () => {
		const preview = await smaliPatch(request());
		await fs.writeFile(output, "keep me");
		await expect(
			smaliPatch(
				request("patch_smali_method", {
					preview_sha256: preview.previewSha256,
				}),
			),
		).rejects.toThrow("already exists");
		expect(await fs.readFile(output, "utf8")).toBe("keep me");
	});
	it("rejects same-file publication and directory sources", async () => {
		await expect(
			smaliPatch({ ...request(), output_file: source }),
		).rejects.toThrow("different");
		await fs.rm(source);
		await fs.mkdir(source);
		await expect(smaliPatch(request())).rejects.toThrow("file");
	});
	it("enforces source byte budget", async () => {
		await fs.writeFile(source, Buffer.alloc(512 * 1024 + 1));
		await expect(smaliPatch(request())).rejects.toThrow("512 KiB");
	});
	it("honors cancellation before publication", async () => {
		const controller = new AbortController();
		controller.abort();
		await expect(smaliPatch(request(), controller.signal)).rejects.toThrow();
		expect(await fs.readdir(root)).toEqual(["source.smali"]);
	});
	it.skipIf(process.platform === "win32")(
		"rejects source and destination-parent symlinks",
		async () => {
			const linked = path.join(root, "linked.smali");
			await fs.symlink(source, linked);
			await expect(
				smaliPatch({ ...request(), target: linked }),
			).rejects.toThrow("symbolic");
			const linkedDir = path.join(root, "dir");
			await fs.symlink(root, linkedDir);
			await expect(
				smaliPatch({
					...request(),
					output_file: path.join(linkedDir, "new.smali"),
				}),
			).rejects.toThrow("symbolic");
		},
	);
	it("preserves CRLF and rejects invalid UTF-8", async () => {
		const crlf = original.replaceAll("\n", "\r\n");
		await fs.writeFile(source, crlf);
		const preview = await smaliPatch(
			request("preview_smali_patch", {
				expected_sha256: hash(crlf),
				expected_method: before.replaceAll("\n", "\r\n"),
				replacement_method: after.replaceAll("\n", "\r\n"),
			}),
		);
		expect(preview.diff.after).toContain("\r\n");
		const invalid = Buffer.from([0xff, 0xfe]);
		await fs.writeFile(source, invalid);
		await expect(
			smaliPatch(
				request("preview_smali_patch", { expected_sha256: hash(invalid) }),
			),
		).rejects.toThrow();
	});
});
