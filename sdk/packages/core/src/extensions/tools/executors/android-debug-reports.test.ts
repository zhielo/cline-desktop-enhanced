import { expect, it } from "vitest";
import {
	collectAndroidDebugReports,
	scopedDebugSections,
} from "./android-debug-reports";

const input = {
	package: "com.example.owned",
	deviceSerial: "owned-serial",
	paths: ["/data/anr/anr_2026-10-07-01-00"],
	useRoot: false,
	confirmSensitive: true,
	acknowledgeRoot: false,
};
function result(text: string) {
	return {
		exitCode: 0,
		stdout: Buffer.from(text),
		stderr: "",
		timedOut: false,
		cancelled: false,
	};
}
it("scopes exact package reports, verifies serial and metadata, and never retains other packages", async () => {
	const text =
			'----- pid 42 -----\nCmd line: com.example.owned\n"main" tid=1 Blocked\n token=private\n----- pid 43 -----\nCmd line: com.other.app\nforeign sensitive data',
		calls: string[][] = [];
	const r = await collectAndroidDebugReports(input, async (args) => {
		calls.push(args);
		return result(
			args[0] === "get-serialno"
				? "owned-serial"
				: args[1].includes("stat -c")
					? `${Buffer.byteLength(text)}:12:100`
					: text,
		);
	});
	const report = r.reports[0];
	expect(report.text).toContain("com.example.owned");
	expect(report.text).not.toContain("foreign");
	expect(report.text).not.toContain("private");
	expect(report.sourceComplete).toBe(true);
	expect(calls.filter((c) => c[0] === "get-serialno")).toHaveLength(2);
	expect(calls.every((c) => !c.join(" ").includes("su -c"))).toBe(true);
});
it("requires a separate root acknowledgement before any read and never falls back after denial", async () => {
	let calls = 0;
	await expect(
		collectAndroidDebugReports({ ...input, useRoot: true }, async () => {
			calls++;
			return result("");
		}),
	).rejects.toThrow("Separate root");
	expect(calls).toBe(0);
	await expect(
		collectAndroidDebugReports(
			{ ...input, useRoot: true, acknowledgeRoot: true },
			async (args) => {
				calls++;
				if (args[0] === "get-serialno") return result("owned-serial");
				return { ...result(""), exitCode: 1 };
			},
		),
	).rejects.toThrow("no root fallback");
	expect(calls).toBe(2);
});
it("rejects report path escapes, duplicates and changed file identities", async () => {
	for (const paths of [
		["/data/anr/../secret"],
		["/data/tombstones/tombstone_00.pb"],
		[input.paths[0], input.paths[0]],
	])
		await expect(
			collectAndroidDebugReports({ ...input, paths }, async () => result("")),
		).rejects.toThrow("exact allowed");
	let stat = 0;
	await expect(
		collectAndroidDebugReports(input, async (args) =>
			result(
				args[0] === "get-serialno"
					? "owned-serial"
					: args[1].includes("stat -c")
						? `4:${++stat}:100`
						: "data",
			),
		),
	).rejects.toThrow("changed during read");
});
it("labels bounded prefixes and missing package markers instead of claiming full capture", async () => {
	const text = "Cmd line: com.example.owned\n" + "x".repeat(200001);
	const r = await collectAndroidDebugReports(input, async (args) =>
		result(
			args[0] === "get-serialno"
				? "owned-serial"
				: args[1].includes("stat -c")
					? `${Buffer.byteLength(text)}:12:100`
					: text,
		),
	);
	expect(r.reports[0].status).toBe("scoped-prefix-only");
	const other = await collectAndroidDebugReports(input, async (args) =>
		result(
			args[0] === "get-serialno"
				? "owned-serial"
				: args[1].includes("stat -c")
					? "10:12:100"
					: "other data",
		),
	);
	expect(other.reports[0].status).toBe("unattributed-not-retained");
	expect(other.reports[0].text).toBeUndefined();
	expect(
		scopedDebugSections("Cmd line: com.example.ownedx", "com.example.owned"),
	).toBe("");
});
