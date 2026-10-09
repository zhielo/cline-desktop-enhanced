import { expect, it } from "vitest";
import {
	latestIdaProgress,
	latestSmaliProgress,
	nativeExecutionFailure,
} from "./native-tool-progress";

it("reads only bounded IDA advisory progress and chooses the most recent record", () => {
	expect(latestIdaProgress("ordinary output")).toBeNull();
	expect(latestIdaProgress(null)).toBeNull();
	expect(
		latestIdaProgress(
			"[IDA progress] starting\n[IDA progress] running; phase: auto-analysis-waiting\n",
		),
	).toBe("running; phase: auto-analysis-waiting");
	expect(latestIdaProgress("[IDA progress] " + "x".repeat(900))).toHaveLength(
		800,
	);
});

it("uses native failure receipts without treating ordinary output or a successful engine as failure", () => {
	expect(
		nativeExecutionFailure(
			JSON.stringify({ engine: "ida", succeeded: false, timedOut: true }),
		),
	).toContain("deadline exceeded");
	expect(
		nativeExecutionFailure({
			result: JSON.stringify({
				engine: "ida",
				succeeded: false,
				outputDrainTimedOut: true,
			}),
		}),
	).toContain("unconfirmed");
	expect(
		nativeExecutionFailure({ engine: "ida", succeeded: true, timedOut: true }),
	).toBeNull();
	expect(nativeExecutionFailure({ succeeded: false })).toBeNull();
	expect(nativeExecutionFailure("arbitrary error text")).toBeNull();
});

it("shows actual bounded scan counters without inventing percentages", () => {
	expect(
		latestSmaliProgress(
			"[Smali scan] stage=scanning; scanned_files=12; bytes_read=4096;\n",
		),
	).toContain("scanned_files=12");
	expect(latestSmaliProgress("running for 30 seconds")).toBeNull();
	expect(latestSmaliProgress("[Smali scan] " + "x".repeat(900))).toHaveLength(
		800,
	);
});
