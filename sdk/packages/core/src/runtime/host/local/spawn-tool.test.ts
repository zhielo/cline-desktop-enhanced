import { describe, expect, it, vi } from "vitest";
import type { SubAgentControlHandle } from "../../../extensions/tools/team";
import {
	controlLiveSubAgent,
	createSessionSubAgentLifecycleCallbacks,
} from "./spawn-tool";

describe("session subagent control registration", () => {
	it("registers a live handle under its owning root and releases only that handle", () => {
		const controls = new Map<
			string,
			{ rootSessionId: string; handle: SubAgentControlHandle }
		>();
		const callbacks = createSessionSubAgentLifecycleCallbacks(
			{
				getSession: () => undefined,
				subAgentStarts: new Map(),
				subAgentControls: controls,
				onAgentEvent: vi.fn(),
				invokeBackendOptional: vi.fn(async () => {}),
			},
			{
				cwd: "/repo",
				providerId: "anthropic",
				modelId: "claude-sonnet-4-6",
				systemPrompt: "Lead",
				mode: "act",
				enableTools: true,
				enableSpawnAgent: true,
				enableAgentTeams: false,
			},
			"root-session",
		);
		const first: SubAgentControlHandle = {
			subAgentId: "sub-1",
			abort: vi.fn(),
			steer: vi.fn(),
		};
		const replacement: SubAgentControlHandle = {
			...first,
			abort: vi.fn(),
			steer: vi.fn(),
		};

		callbacks.onSubAgentControlReady(first);
		expect(controls.get("sub-1")).toEqual({
			rootSessionId: "root-session",
			handle: first,
		});
		callbacks.onSubAgentControlReady(replacement);
		callbacks.onSubAgentControlReleased(first);
		expect(controls.get("sub-1")?.handle).toBe(replacement);
		callbacks.onSubAgentControlReleased(replacement);
		expect(controls.has("sub-1")).toBe(false);
	});

	it("enforces root ownership and routes stop or steer to one live child", () => {
		const abort = vi.fn();
		const steer = vi.fn();
		const controls = new Map([
			[
				"sub-1",
				{
					rootSessionId: "root-a",
					handle: { subAgentId: "sub-1", abort, steer },
				},
			],
		]);

		expect(
			controlLiveSubAgent(controls, "root-b", {
				agentId: "sub-1",
				action: "stop",
			}),
		).toBeUndefined();
		expect(abort).not.toHaveBeenCalled();
		expect(
			controlLiveSubAgent(controls, "root-a", {
				agentId: "sub-1",
				action: "steer",
				message: "  focus on tests  ",
			}),
		).toBe("steered");
		expect(steer).toHaveBeenCalledWith("focus on tests");
		expect(
			controlLiveSubAgent(controls, "root-a", {
				agentId: "sub-1",
				action: "stop",
			}),
		).toBe("cancelled");
		expect(abort).toHaveBeenCalledWith("cancelled_from_desktop");
		expect(() =>
			controlLiveSubAgent(controls, "root-a", {
				agentId: "sub-1",
				action: "retry",
			}),
		).toThrow("cannot be retried independently");
	});
});
