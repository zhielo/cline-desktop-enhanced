import { expect, it, vi } from "vitest";
const mocks = vi.hoisted(() => ({
	cleanup: vi.fn(async () => 2),
	snapshot: vi.fn(() => ({
		scope: "owning-process",
		profile: "balanced",
		active: 0,
		queued: 0,
	})),
}));
vi.mock("@cline/core", () => ({
	analysisResourceGovernor: { snapshot: mocks.snapshot, setProfile: vi.fn() },
	getPowerShellWorkerBaselineDecision: () => ({
		status: "collecting",
		directSamples: 2,
		shellSamples: 3,
		reason: "Insufficient evidence",
	}),
	cleanupStaleDetachedCommandLogs: mocks.cleanup,
}));
vi.mock("./trusted-update", () => ({
	privateUpdateReadiness: () => ({ reason: "Private unsigned builds" }),
}));
import {
	cleanupCompletedCommandLogs,
	optimizationStatus,
} from "./optimization-status";
it("exposes measured command collection without pretending there is an installed performance baseline", () => {
	expect(optimizationStatus()).toMatchObject({
		performance: {
			status: "baseline-required",
			commandLatency: { status: "collecting" },
		},
		resources: { scope: "owning-process" },
	});
});
it("uses existing active-identity-aware expired-log cleanup without deleting runtimes or sessions", async () => {
	expect(await cleanupCompletedCommandLogs()).toMatchObject({
		removed: 2,
		message: expect.stringContaining("runtime packs were not deleted"),
	});
	expect(mocks.cleanup).toHaveBeenCalledWith();
});
