// @vitest-environment jsdom

import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { WORKSPACE_SELECTION_STORAGE_KEY } from "@/lib/workspace-paths";
import { EngineeringWorkspace } from "./engineering-workspace";

const mocks = vi.hoisted(() => ({ invoke: vi.fn() }));
vi.mock("@/lib/desktop-client", () => ({ desktopClient: mocks }));

let container: HTMLDivElement;
let root: Root;
const snapshot = {
	profile: {
		workspaceRoot: "C:\\work\\app",
		name: "app",
		isGitRepository: true,
		branch: "main",
		languages: [{ language: "TypeScript", files: 42 }],
		packageManagers: ["Bun"],
		buildCommands: ["bun run build"],
		testCommands: ["bun run test"],
		ciProviders: ["GitHub Actions"],
		sensitivePaths: [],
	},
	policy: {
		defaultTier: "restricted",
		network: "deny",
		maxRuntimeMinutes: 20,
		maxProcesses: 32,
		requireSandboxFor: ["unknown-binary"],
		requireWorktreeForWrites: true,
		requireIndependentReview: true,
	},
	missions: [],
	health: {
		durableState: true,
		journalMode: "WAL",
		recovery: "enabled",
		normalChatIsolation: true,
		activeMissions: 0,
		securityPosture: "hardened",
	},
};

beforeEach(() => {
	Object.assign(globalThis, { IS_REACT_ACT_ENVIRONMENT: true });
	localStorage.setItem(
		WORKSPACE_SELECTION_STORAGE_KEY,
		JSON.stringify({
			environments: {
				local: {
					lastWorkspace: "C:\\work\\app",
					workspaces: ["C:\\work\\app"],
				},
			},
		}),
	);
	mocks.invoke.mockResolvedValue(snapshot);
	container = document.createElement("div");
	document.body.appendChild(container);
	root = createRoot(container);
});
afterEach(async () => {
	await act(async () => root.unmount());
	container.remove();
	localStorage.clear();
	vi.clearAllMocks();
});

describe("EngineeringWorkspace", () => {
	it("loads a separate hardened control center without changing normal chat", async () => {
		await act(async () => {
			root.render(<EngineeringWorkspace />);
			await Promise.resolve();
		});
		await vi.waitFor(() =>
			expect(container.textContent).toContain("Engineering Control Center"),
		);
		expect(container.textContent).toContain(
			"Normal Cline chat remains unchanged",
		);
		expect(container.textContent).toContain("hardened");
		expect(mocks.invoke).toHaveBeenCalledWith("get_engineering_workspace", {
			cwd: "C:\\work\\app",
		});
	});
	it("creates only a durable plan when Plan mission is selected", async () => {
		await act(async () => {
			root.render(<EngineeringWorkspace />);
			await Promise.resolve();
		});
		await vi.waitFor(() =>
			expect(container.querySelector("button")).not.toBeNull(),
		);
		const button = [...container.querySelectorAll("button")].find((item) =>
			item.textContent?.includes("Plan mission"),
		);
		await act(async () => {
			button?.dispatchEvent(new MouseEvent("click", { bubbles: true }));
			await Promise.resolve();
		});
		expect(mocks.invoke).toHaveBeenCalledWith(
			"plan_engineering_mission",
			expect.objectContaining({ cwd: "C:\\work\\app" }),
		);
	});
});
