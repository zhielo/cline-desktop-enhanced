import { test, expect } from "bun:test";
import { isolationHostFailureMessage } from "../sidecar/isolation-host-failure";
const owned = {
	schemaVersion: 1,
	error: "isolation-launch-failed",
	stage: "launch",
	win32Error: 5,
	hresult: -2147024891,
	cleanupFailures: [],
};
test("retains bounded stage and native status without exception text or paths", () => {
	expect(isolationHostFailureMessage(JSON.stringify(owned))).toContain(
		"stage=launch; win32=5; hresult=0x80070005",
	);
});
test("preserves original stage when cleanup also fails", () => {
	expect(
		isolationHostFailureMessage(
			JSON.stringify({
				...owned,
				cleanupFailures: ["profile-cleanup", "staging-cleanup"],
			}),
		),
	).toContain("stage=launch");
	expect(
		isolationHostFailureMessage(
			JSON.stringify({ ...owned, cleanupFailures: ["staging-cleanup"] }),
		),
	).toContain("cleanup=staging-cleanup");
});
for (const bad of [
	{ ...owned, stage: "target-secret" },
	{ ...owned, message: "secret" },
	{ ...owned, win32Error: "5" },
	{ ...owned, hresult: 1.5 },
	{ ...owned, cleanupFailures: ["secret"] },
	{ error: "target claims success" },
	[owned],
])
	test("rejects untrusted/malformed diagnostic structure", () => {
		const m = isolationHostFailureMessage(JSON.stringify(bad));
		expect(m).toBe(
			"OS isolation failed closed before a successful receipt; no fallback",
		);
		expect(m).not.toContain("secret");
	});
test("rejects oversized and invalid output", () => {
	expect(isolationHostFailureMessage("x".repeat(4097))).not.toContain("stage=");
	expect(isolationHostFailureMessage("invalid JSON")).not.toContain("stage=");
});

import { isolationHostEnvironment } from "../sidecar/isolation-host-environment";
const host = {
	APPDATA: "C:\\Users\\owned\\AppData\\Roaming",
	LOCALAPPDATA: "C:\\Users\\owned\\AppData\\Local",
	SystemRoot: "C:\\Windows",
	USERPROFILE: "C:\\Users\\owned",
};
test("helper bootstrap uses only reviewed OS variables, never API/PATH/options", () => {
	const env = isolationHostEnvironment(
		{
			...host,
			PATH: "secret-path",
			API_KEY: "secret",
			NODE_OPTIONS: "secret",
			HOME: "secret",
		},
		"C:\\Temp",
	);
	expect(Object.keys(env)).toEqual([
		"APPDATA",
		"LOCALAPPDATA",
		"SystemRoot",
		"TEMP",
		"TMP",
		"USERPROFILE",
	]);
	expect(JSON.stringify(env)).not.toContain("secret");
});
test("helper bootstrap fails closed on absent or malformed OS profile variables", () => {
	for (const bad of [
		{ ...host, USERPROFILE: undefined },
		{ ...host, LOCALAPPDATA: "relative" },
		{ ...host, APPDATA: "C:\\bad\0" },
	])
		expect(() => isolationHostEnvironment(bad, "C:\\Temp")).toThrow();
});

// Source guard complements (never substitutes for) the actual Windows denial test.
import { readFileSync } from "node:fs";
test("native policy explicitly limits the job to one process before target resume", () => {
	const native = readFileSync(
		new URL("../native/JavaScriptIsolation.cs", import.meta.url),
		"utf8",
	);
	expect(native).toContain("limits.basic.active=1;");
	expect(native).toContain("limits.basic.flags=0x2000|0x8|0x200;");
	expect(native.indexOf("SetInformationJobObject(job,9")).toBeLessThan(
		native.indexOf("ResumeThread(child.thread)"),
	);
});

import { finalizeIsolationCleanup } from "../sidecar/isolation-cleanup";
test("validated native host receipt avoids racing a redundant profile delete", async () => {
	const calls: string[] = [];
	await finalizeIsolationCleanup(
		true,
		() => {
			calls.push("profile");
			throw new Error("redundant delete must not run");
		},
		() => {
			calls.push("stage");
		},
	);
	expect(calls).toEqual(["stage"]);
});
test("unconfirmed host cleanup still requires controller profile and stage cleanup", async () => {
	const calls: string[] = [];
	await finalizeIsolationCleanup(
		false,
		() => {
			calls.push("profile");
		},
		() => {
			calls.push("stage");
		},
	);
	expect(calls).toEqual(["profile", "stage"]);
});
test("failed controller profile cleanup remains a failure but stage removal is still attempted", async () => {
	const calls: string[] = [];
	await expect(
		finalizeIsolationCleanup(
			false,
			() => {
				calls.push("profile");
				throw new Error("profile cleanup unconfirmed");
			},
			() => {
				calls.push("stage");
			},
		),
	).rejects.toThrow("profile cleanup unconfirmed");
	expect(calls).toEqual(["profile", "stage"]);
});
test("unconfirmed stage cleanup discards even a validated host receipt", async () => {
	await expect(
		finalizeIsolationCleanup(
			true,
			() => {},
			() => {
				throw new Error("stage cleanup unconfirmed");
			},
		),
	).rejects.toThrow("stage cleanup unconfirmed");
});
test("native success exit follows required profile and staging cleanup", () => {
	const native = readFileSync(
		new URL("../native/JavaScriptIsolation.cs", import.meta.url),
		"utf8",
	);
	expect(native).toContain(
		'if(profile && DeleteAppContainerProfile(name)!=0) CleanupFailure(ref receipt,"profile-cleanup",ref code);',
	);
	expect(native).toContain(
		'if(!removed) CleanupFailure(ref receipt,"staging-cleanup",ref code);',
	);
	expect(native).toContain(
		'((List<string>)receipt["cleanupFailures"]).Add(stage);code=1;',
	);
	expect(
		native.indexOf("if(profile && DeleteAppContainerProfile(name)!=0)"),
	).toBeLessThan(
		native.lastIndexOf(
			"Console.WriteLine(new JavaScriptSerializer().Serialize(receipt)); return code;",
		),
	);
	const controller = readFileSync(
		new URL("../sidecar/javascript-isolation.ts", import.meta.url),
		"utf8",
	);
	expect(controller.indexOf("hostReceiptVerified = true")).toBeGreaterThan(
		controller.indexOf("const receipt = Receipt.parse(JSON.parse(encoded));"),
	);
	expect(controller).toContain("code !== 0");
});
