import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
	EngineeringControlPlane,
	evaluateExecutionPolicy,
	routeEngineeringModel,
	scoreReviewRisk,
} from "./engineering-control-plane";

const roots: string[] = [];
function fixture() {
	const root = mkdtempSync(join(tmpdir(), "cline-engineering-"));
	roots.push(root);
	mkdirSync(join(root, ".github", "workflows"), { recursive: true });
	writeFileSync(
		join(root, "package.json"),
		JSON.stringify({ scripts: { build: "tsc", test: "vitest" } }),
	);
	writeFileSync(join(root, "app.ts"), "export const answer = 42\n");
	writeFileSync(join(root, "bun.lock"), "");
	return root;
}
afterEach(() => {
	for (const root of roots.splice(0))
		rmSync(root, { recursive: true, force: true });
});

describe("EngineeringControlPlane", () => {
	it("persists hardened workspace policy and plans an isolated mission DAG", () => {
		const root = fixture();
		const plane = new EngineeringControlPlane(join(root, "state.db"));
		const snapshot = plane.getWorkspace(root);
		expect(snapshot.profile.languages[0]).toEqual({
			language: "TypeScript",
			files: 1,
		});
		expect(snapshot.profile.packageManagers).toContain("Bun");
		expect(snapshot.policy.network).toBe("deny");
		const mission = plane.planMission(root, { title: "Ship safely" });
		expect(
			mission.tasks
				.filter((task) => task.writesRepository)
				.every((task) => task.requiresWorktree),
		).toBe(true);
		expect(plane.getWorkspace(root).missions[0]?.title).toBe("Ship safely");
		plane.close();
	});

	it("rejects cyclic missions", () => {
		const root = fixture();
		const plane = new EngineeringControlPlane(join(root, "state.db"));
		expect(() =>
			plane.planMission(root, {
				tasks: [
					{ id: "a", dependsOn: ["b"] },
					{ id: "b", dependsOn: ["a"] },
				],
			}),
		).toThrow("cycle");
		plane.close();
	});
});

describe("engineering policies", () => {
	it("requires an isolated VM for unknown binaries and blocks host network/write escape", () => {
		const decision = evaluateExecutionPolicy(undefined, {
			categories: ["unknown-binary"],
			writes: true,
			network: true,
			worktree: false,
		});
		expect(decision).toMatchObject({
			allowed: false,
			requiredTier: "isolated-vm",
			network: "deny",
		});
		expect(decision.reasons).toHaveLength(2);
	});
	it("scores risky reviews and prevents merging", () => {
		expect(
			scoreReviewRisk({
				changedLines: 1500,
				sensitiveFiles: ["auth.ts"],
				dependenciesChanged: true,
				failedChecks: 1,
				testsAdded: false,
			}),
		).toMatchObject({ level: "critical", mergeAllowed: false });
	});
	it("routes to the strongest capable model while preserving user-visible ranking", () => {
		const result = routeEngineeringModel(
			{ requiredCapabilities: ["tools"], minimumContext: 100_000 },
			[
				{
					id: "fast",
					provider: "a",
					capabilities: ["tools"],
					contextWindow: 200_000,
					successRate: 0.7,
					toolReliability: 0.7,
					latencyMs: 400,
				},
				{
					id: "strong",
					provider: "b",
					capabilities: ["tools"],
					contextWindow: 200_000,
					successRate: 0.95,
					toolReliability: 0.98,
					latencyMs: 1_500,
				},
			],
		);
		expect(result.selected?.id).toBe("strong");
	});
});
