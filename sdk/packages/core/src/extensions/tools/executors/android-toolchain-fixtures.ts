import { createHash, randomBytes } from "node:crypto";
/** Fixed owned static corpus. Never installs, launches or instruments an Android application. */
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { ownedZip } from "./android-owned-zip";
import {
	androidChildEnvironment,
	runAndroidTool,
	verifyAndroidToolchain,
} from "./android-toolchain";
import { runSupervised as runBaseSupervised } from "./supervised-process";

export async function testAndroidToolchain(signal?: AbortSignal) {
	const pack = await verifyAndroidToolchain();
	const { createReverseEngineeringExecutor } = await import(
		"./reverse-engineering"
	);
	const execute = createReverseEngineeringExecutor();
	const root = await fs.mkdtemp(
		path.join(os.tmpdir(), "cline Android owned 测试 "),
	);
	const checks: Record<string, string> = {};
	let preserve = false;
	async function runSupervised(...args: Parameters<typeof runBaseSupervised>) {
		const [command, argv, timeout, childSignal, , environment] = args;
		const jar = command === pack.java && argv[0] === "-jar";
		const keytool =
			command ===
			path.join(
				pack.root,
				process.platform === "win32"
					? "jre/bin/keytool.exe"
					: "jre/bin/keytool",
			);
		const result =
			jar ||
			keytool ||
			["aapt2", "zipalign", "dexdump"].some(
				(tool) => command === path.join(pack.root, `build-tools/${tool}.exe`),
			)
				? await runAndroidTool(
						jar ? argv[1] : command,
						jar ? argv.slice(2) : argv,
						timeout,
						childSignal,
						environment,
					)
				: await runBaseSupervised(...args);
		preserve ||= result.outputDrainTimedOut === true;
		return result;
	}
	async function call(input: Record<string, unknown>) {
		const result = JSON.parse(
			await execute(
				{ engine: "auto", timeout_ms: 120000, ...input } as never,
				{ signal } as never,
			),
		);
		if (result.outputDrainTimedOut) preserve = true;
		if (
			result.succeeded === false ||
			(result.exitCode !== undefined && result.exitCode !== 0) ||
			result.cancelled ||
			result.timedOut ||
			result.outputDrainTimedOut
		)
			throw new Error(
				`Owned Android ${input.operation} fixture failed (exit ${result.exitCode ?? "unknown"}): ${JSON.stringify({ timedOut: result.timedOut, cancelled: result.cancelled, drain: result.outputDrainTimedOut, succeeded: result.succeeded, stdout: String(result.stdout ?? "").slice(0, 1000), stderr: String(result.stderr ?? "").slice(0, 2000) })}`,
			);
		return result;
	}
	try {
		const project = path.join(root, "project"),
			smali = path.join(project, "smali/com/cline/owned");
		await fs.mkdir(smali, { recursive: true });
		await fs.writeFile(
			path.join(smali, "Fixture.smali"),
			".class public Lcom/cline/owned/Fixture;\n.super Ljava/lang/Object;\n.method public static answer()I\n .registers 1\n const/16 v0, 0x2a\n return v0\n.end method\n",
		);
		const secondary = path.join(project, "smali_classes2/com/cline/owned");
		await fs.mkdir(secondary, { recursive: true });
		await fs.writeFile(
			path.join(secondary, "Second.smali"),
			".class public Lcom/cline/owned/Second;\n.super Ljava/lang/Object;\n.method public static value()I\n .registers 1\n const/4 v0, 0x7\n return v0\n.end method\n",
		);
		await fs.writeFile(
			path.join(project, "AndroidManifest.xml"),
			'<?xml version="1.0" encoding="utf-8"?><manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.cline.owned" android:versionCode="1" android:versionName="1"><uses-sdk android:minSdkVersion="23" android:targetSdkVersion="35"/><application android:label="@string/app_name" android:hasCode="true"/></manifest>',
		);
		await fs.mkdir(path.join(project, "res/values"), { recursive: true });
		await fs.writeFile(
			path.join(project, "res/values/strings.xml"),
			'<resources><string name="app_name">Cline owned fixture</string></resources>',
		);
		await fs.writeFile(
			path.join(project, "apktool.yml"),
			'version: 3.0.3\napkFileName: owned.apk\nusesFramework:\n  ids:\n  - 1\nsdkInfo:\n  minSdkVersion: 23\n  targetSdkVersion: 35\nversionInfo:\n  versionCode: 1\n  versionName: "1"\n',
		);
		const dex = path.join(root, "owned.dex");
		await call({
			operation: "assemble_smali",
			target: path.join(project, "smali"),
			output_file: dex,
			smali_api_level: 28,
		});
		checks.smali = "owned-DEX-header-digests-passed";
		const decodedDex = path.join(root, "DEX decoded");
		await call({
			operation: "disassemble_smali",
			target: dex,
			output_directory: decodedDex,
			smali_api_level: 28,
		});
		checks.baksmali = "owned-DEX-disassembly-passed";
		const method = await call({
			operation: "read_smali_method",
			target: path.join(decodedDex, "com/cline/owned/Fixture.smali"),
			smali_method: "answer()I",
		});
		if (!JSON.stringify(method).includes("0x2a"))
			throw new Error("Owned exact method missing");
		const apk = path.join(root, "owned unsigned.apk");
		await call({ operation: "rebuild_apk", target: project, output_file: apk });
		const decoded = path.join(root, "APK decoded");
		await call({
			operation: "disassemble_smali",
			target: apk,
			output_directory: decoded,
		});
		await fs.access(
			path.join(decoded, "smali_classes2/com/cline/owned/Second.smali"),
		);
		await fs.access(path.join(decoded, "res/values/strings.xml"));
		const rebuilt = path.join(root, "rebuilt.apk");
		await call({
			operation: "rebuild_apk",
			target: decoded,
			output_file: rebuilt,
		});
		checks.apktool = "owned-resource-and-multidex-round-trip-passed";

		// Real engines, not a mock receipt: preview, patch a private project, assemble
		// both DEX roots, rebuild with Apktool, decode, and check the exact edit.
		const sourceFile = path.join(smali, "Fixture.smali");
		const sourceText = await fs.readFile(sourceFile, "utf8");
		const beforeMethod =
			".method public static answer()I\n .registers 1\n const/16 v0, 0x2a\n return v0\n.end method";
		const projectPatch = {
			patches: [
				{
					path: "smali/com/cline/owned/Fixture.smali",
					patch: {
						expected_sha256: createHash("sha256")
							.update(sourceText)
							.digest("hex"),
						class_descriptor: "Lcom/cline/owned/Fixture;",
						method_signature: "answer()I",
						expected_method: beforeMethod,
						replacement_method: beforeMethod.replace("0x2a", "0x2b"),
					},
				},
			],
		};
		const projectOutput = path.join(root, "approved patched.apk");
		const preview = await call({
			operation: "preview_android_candidate",
			target: project,
			output_file: projectOutput,
			android_project_patch: projectPatch,
			smali_api_level: 28,
		});
		if (
			preview.status !== "completed" ||
			preview.published ||
			preview.executed !== false
		)
			throw new Error("Owned project preview failed");
		const patched = await call({
			operation: "build_android_candidate",
			target: project,
			output_file: projectOutput,
			smali_api_level: 28,
			android_project_patch: {
				...projectPatch,
				expected_project_sha256: preview.projectSha256,
				preview_sha256: preview.previewSha256,
			},
		});
		if (
			patched.status !== "completed" ||
			!patched.published ||
			!patched.sourceUnchanged ||
			!patched.stages.some(
				(s: { id: string }) => s.id === "assemble-smali_classes2",
			) ||
			(await fs.readFile(sourceFile, "utf8")) !== sourceText
		)
			throw new Error("Owned project build or original preservation failed");
		const patchedDecoded = path.join(root, "patched APK decoded");
		await call({
			operation: "disassemble_smali",
			target: projectOutput,
			output_directory: patchedDecoded,
		});
		const patchedMethod = await call({
			operation: "read_smali_method",
			target: path.join(patchedDecoded, "smali/com/cline/owned/Fixture.smali"),
			smali_method: "answer()I",
		});
		if (!JSON.stringify(patchedMethod).includes("0x2b"))
			throw new Error("Owned built APK did not retain approved method edit");
		await fs.access(
			path.join(patchedDecoded, "smali_classes2/com/cline/owned/Second.smali"),
		);
		checks.projectCandidate =
			"owned-preview-patch-all-dex-assemble-apktool-decode-original-preserved-passed";

		const java = await call({
			operation: "decompile",
			engine: "jadx",
			target: dex,
			output_directory: path.join(root, "Java view"),
			jadx_single_class: "com.cline.owned.Fixture",
		});
		if (!JSON.stringify(java).includes("Fixture"))
			throw new Error("Owned JADX class view unavailable");
		checks.jadx = "owned-class-decompilation-passed";
		const bundletool = await runSupervised(
			pack.java,
			["-jar", path.join(pack.root, "bundletool.jar"), "version"],
			30000,
			signal,
			undefined,
			androidChildEnvironment(),
			true,
		);
		if (bundletool.exitCode !== 0 || !bundletool.stdout.includes("1.18.3"))
			throw new Error("Owned Bundletool launch failed");
		checks.bundletool =
			"pinned-version-launch-passed; valid-AAB-corpus-not-claimed";
		const invalid = await fs.readFile(apk);
		const bundle = path.join(root, "invalid.aab");
		await fs.writeFile(bundle, invalid);
		const rejected = JSON.parse(
			await execute(
				{
					engine: "auto",
					operation: "validate_android_container",
					target: bundle,
					timeout_ms: 30000,
				},
				{ signal } as never,
			),
		);
		if (
			rejected.validated !== false ||
			typeof rejected.exitCode !== "number" ||
			rejected.exitCode === 0 ||
			rejected.timedOut ||
			rejected.cancelled ||
			rejected.outputDrainTimedOut
		)
			throw new Error("Invalid AAB rejection was not established");
		checks.bundletool += "; invalid-AAB-rejection-passed";

		const splits = path.join(root, "owned.apks");
		await fs.writeFile(
			splits,
			ownedZip([{ name: "base-master.apk", bytes: await fs.readFile(apk) }]),
		);
		const inventory = await call({
			operation: "validate_android_container",
			target: splits,
		});
		if (inventory.apkMembers?.[0] !== "base-master.apk")
			throw new Error("Owned split inventory failed");
		let blocked = false;
		try {
			await execute(
				{ engine: "auto", operation: "disassemble_smali", target: splits },
				{ signal } as never,
			);
		} catch {
			blocked = true;
		}
		if (!blocked) throw new Error("Split container routed as ordinary APK");
		checks.splitContainers =
			"owned-inventory-and-ordinary-APK-routing-denial-passed";
		// A throwaway key exists only for this fixture, never in resources, evidence or the workspace.
		const keytool = path.join(
				pack.root,
				"jre/bin",
				process.platform === "win32" ? "keytool.exe" : "keytool",
			),
			keystore = path.join(root, "owned-test-key.p12"),
			password = randomBytes(24).toString("hex");
		const key = await runSupervised(
			keytool,
			[
				"-genkeypair",
				"-alias",
				"owned-fixture",
				"-keyalg",
				"RSA",
				"-keysize",
				"2048",
				"-validity",
				"1",
				"-dname",
				"CN=Cline Owned Fixture",
				"-storetype",
				"PKCS12",
				"-keystore",
				keystore,
				"-storepass:env",
				"CLINE_FIXTURE_PASS",
				"-keypass:env",
				"CLINE_FIXTURE_PASS",
				"-noprompt",
			],
			30000,
			signal,
			undefined,
			androidChildEnvironment({ CLINE_FIXTURE_PASS: password }),
			true,
		);
		if (key.exitCode !== 0)
			throw new Error("Owned ephemeral key fixture failed");
		// Pass disposable fixture secrets to this one child only; never mutate host signing configuration.
		const signed = path.join(root, "signed.apk");
		const signature = await runSupervised(
			pack.java,
			[
				"-jar",
				path.join(pack.root, "build-tools/lib/apksigner.jar"),
				"sign",
				"--ks",
				keystore,
				"--ks-key-alias",
				"owned-fixture",
				"--ks-pass",
				"env:CLINE_FIXTURE_PASS",
				"--key-pass",
				"env:CLINE_FIXTURE_PASS",
				"--out",
				signed,
				rebuilt,
			],
			30000,
			signal,
			undefined,
			androidChildEnvironment({ CLINE_FIXTURE_PASS: password }),
			true,
		);
		if (
			signature.exitCode !== 0 ||
			signature.timedOut ||
			signature.cancelled ||
			signature.outputDrainTimedOut
		)
			throw new Error("Owned ephemeral signature fixture failed");
		const verified = await call({
			operation: "verify_apk_signature",
			target: signed,
		});
		if (!verified.verified)
			throw new Error("Owned signing verification failed");
		checks.apksigner = "ephemeral-owned-key-signature-round-trip-passed";

		if (process.platform === "win32") {
			await call({
				operation: "align_apk",
				target: rebuilt,
				output_file: path.join(root, "aligned.apk"),
			});
			checks.zipalign = "owned-16KiB-alignment-passed";
			const proto = path.join(root, "proto.apk"),
				converted = await runSupervised(
					path.join(pack.root, "build-tools/aapt2.exe"),
					["convert", "--output-format", "proto", "-o", proto, apk],
					30000,
					signal,
					undefined,
					androidChildEnvironment(),
					true,
				);
			if (
				converted.exitCode !== 0 ||
				converted.timedOut ||
				converted.outputDrainTimedOut ||
				converted.cancelled
			)
				throw new Error("Owned AAB proto resources conversion failed");
			const protoDir = path.join(root, "proto extracted");
			await call({
				operation: "extract",
				target: proto,
				output_directory: protoDir,
			});
			const members: Array<{ name: string; bytes: Buffer }> = [];
			async function visit(dir: string, prefix = "") {
				for (const entry of await fs.readdir(dir, { withFileTypes: true })) {
					const name = prefix + entry.name,
						file = path.join(dir, entry.name);
					if (entry.isDirectory()) await visit(file, name + "/");
					else if (name === "AndroidManifest.xml")
						members.push({
							name: "manifest/AndroidManifest.xml",
							bytes: await fs.readFile(file),
						});
					else if (/^classes(?:[0-9]+)?\.dex$/.test(name))
						members.push({
							name: "dex/" + name,
							bytes: await fs.readFile(file),
						});
					else if (name === "resources.pb" || name.startsWith("res/"))
						members.push({ name, bytes: await fs.readFile(file) });
				}
			}
			await visit(protoDir);
			const module = path.join(root, "base.zip"),
				aab = path.join(root, "owned.aab");
			await fs.writeFile(module, ownedZip(members));
			const built = await runSupervised(
				pack.java,
				[
					"-jar",
					path.join(pack.root, "bundletool.jar"),
					"build-bundle",
					`--modules=${module}`,
					`--output=${aab}`,
				],
				30000,
				signal,
				undefined,
				androidChildEnvironment(),
				true,
			);
			if (
				built.exitCode !== 0 ||
				built.timedOut ||
				built.outputDrainTimedOut ||
				built.cancelled
			)
				throw new Error("Owned AAB build fixture failed");
			const valid = await call({
				operation: "validate_android_container",
				target: aab,
			});
			if (!valid.validated) throw new Error("Owned valid AAB rejected");
			checks.bundletool = "owned-valid-AAB-and-invalid-AAB-validation-passed";

			for (const tool of ["aapt2", "dexdump"]) {
				const result = await runSupervised(
					path.join(pack.root, `build-tools/${tool}.exe`),
					tool === "aapt2" ? ["dump", "badging", apk] : [dex],
					30000,
					signal,
					undefined,
					androidChildEnvironment(),
					true,
				);
				if (
					result.exitCode !== 0 ||
					result.outputDrainTimedOut ||
					result.cancelled ||
					result.timedOut
				)
					throw new Error(`Owned ${tool} inspection failed`);
				checks[tool] = "owned-artifact-inspection-passed";
			}
		} else
			checks.windowsNativeTools =
				"unsupported-on-local-Linux; Windows-CI-required";
		return {
			schemaVersion: 1,
			identity: pack.identity,
			status: "passed",
			checkedAt: new Date().toISOString(),
			checks,
			coverage:
				"Owned static fixtures only; no arbitrary-target, valid-AAB, ART, physical-device or licensed-engine compatibility claim",
		};
	} finally {
		if (!preserve) await fs.rm(root, { recursive: true, force: true });
	}
}
