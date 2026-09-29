// @vitest-environment jsdom

import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
	APP_FONT_SIZE_STORAGE_KEY,
	applyAppZoomAction,
} from "@/lib/app-font-size";
import { PERMISSION_PROFILE_CAPABILITIES, SettingsView } from "./settings-view";

const { invoke } = vi.hoisted(() => ({ invoke: vi.fn() }));
vi.mock("@/lib/desktop-client", () => ({
	desktopClient: { invoke },
	isTauriAvailable: vi.fn(() => false),
	openExternalUrl: vi.fn(),
}));

let container: HTMLDivElement;
let root: Root;

class ResizeObserverStub {
	disconnect() {}
	observe() {}
	unobserve() {}
}

beforeEach(() => {
	Object.assign(globalThis, {
		IS_REACT_ACT_ENVIRONMENT: true,
		ResizeObserver: ResizeObserverStub,
	});
	if (typeof window.localStorage.clear !== "function") {
		Object.defineProperty(window, "localStorage", {
			configurable: true,
			value: window.sessionStorage,
		});
	}
	window.localStorage.clear();
	document.documentElement.style.removeProperty("font-size");
	delete document.documentElement.dataset.clineFontSize;
	invoke.mockReset();
	invoke.mockResolvedValue({
		telemetryOptOut: false,
		autoUpdateEnabled: true,
	});
	container = document.createElement("div");
	document.body.appendChild(container);
	root = createRoot(container);
});

afterEach(async () => {
	await act(async () => root.unmount());
	container.remove();
});

describe("SettingsView permission capability matrix", () => {
	it("shows Full Access as the superset that includes web and interactive browser tools", () => {
		const byLabel = new Map(
			PERMISSION_PROFILE_CAPABILITIES.map((item) => [item.label, item.values]),
		);
		expect(byLabel.get("Web search, fetch, and network")).toEqual([
			false,
			false,
			true,
			true,
		]);
		expect(byLabel.get("Built-in browser")).toEqual([
			false,
			false,
			"Navigate + inspect",
			"Full interaction",
		]);
		expect(byLabel.get("Plugin, MCP, and unclassified tools")?.at(-1)).toBe(
			true,
		);
	});
});

describe("SettingsView font size", () => {
	it("loads the saved size and updates it from the General settings controls", async () => {
		window.localStorage.setItem(APP_FONT_SIZE_STORAGE_KEY, "17");

		await act(async () => {
			root.render(
				<SettingsView onNavigateSection={vi.fn()} section="General" />,
			);
		});

		const slider = container.querySelector<HTMLElement>(
			'[role="slider"][aria-label="Font size"]',
		);
		const increaseButton = container.querySelector<HTMLButtonElement>(
			'button[aria-label="Increase font size"]',
		);
		expect(slider?.getAttribute("aria-valuenow")).toBe("17");
		expect(increaseButton).not.toBeNull();
		expect(increaseButton?.disabled).toBe(false);
		expect(container.textContent).toContain("17px");

		await act(async () => {
			increaseButton?.click();
		});

		expect(window.localStorage.getItem(APP_FONT_SIZE_STORAGE_KEY)).toBe("18");
		expect(document.documentElement.style.fontSize).toBe("18px");
		const updatedSlider = container.querySelector<HTMLElement>(
			'[role="slider"][aria-label="Font size"]',
		);
		expect(updatedSlider).toBe(slider);
		expect(updatedSlider?.getAttribute("aria-valuenow")).toBe("18");

		await act(async () => {
			updatedSlider?.focus();
			updatedSlider?.dispatchEvent(
				new KeyboardEvent("keydown", { bubbles: true, key: "ArrowRight" }),
			);
		});

		expect(window.localStorage.getItem(APP_FONT_SIZE_STORAGE_KEY)).toBe("19");
		expect(document.documentElement.style.fontSize).toBe("19px");
		expect(updatedSlider?.getAttribute("aria-valuenow")).toBe("19");

		await act(async () => {
			applyAppZoomAction("zoom-in");
		});

		expect(window.localStorage.getItem(APP_FONT_SIZE_STORAGE_KEY)).toBe("20");
		expect(container.textContent).toContain("20px");
		expect(updatedSlider?.getAttribute("aria-valuenow")).toBe("20");
		expect(increaseButton?.disabled).toBe(true);
	});
});

describe("SettingsView cloud sessions rollout", () => {
	it.each([
		{
			caseName: "the rollout explicitly enables it",
			featureFlags: { cloudAgents: false, cloudAgentsAvailable: true },
			visible: true,
		},
		{
			caseName: "feature flags are unavailable",
			featureFlags: new Error("feature flags unavailable"),
			visible: false,
		},
	])("shows the preview setting only when $caseName", async ({
		featureFlags,
		visible,
	}) => {
		invoke.mockImplementation(async (command: string) => {
			if (command === "get_feature_flags") {
				if (featureFlags instanceof Error) throw featureFlags;
				return featureFlags;
			}
			if (command === "get_desktop_settings") {
				return { cloudSessionsEnabled: false };
			}
			return {
				telemetryOptOut: false,
				autoUpdateEnabled: true,
			};
		});

		await act(async () => {
			root.render(
				<SettingsView onNavigateSection={vi.fn()} section="General" />,
			);
		});
		await vi.waitFor(() =>
			expect(
				container.querySelector(
					'[role="switch"][aria-label="Cloud sessions"]',
				) !== null,
			).toBe(visible),
		);
	});
});

describe("SettingsView custom AI instructions", () => {
	it("shows saved instructions and persists edits permanently", async () => {
		invoke.mockImplementation(async (command: string, args?: unknown) => {
			if (command === "get_desktop_settings") {
				return {
					cloudSessionsEnabled: false,
					customAiInstructions: "Always show the plan.",
				};
			}
			if (command === "set_custom_ai_instructions") {
				return {
					cloudSessionsEnabled: false,
					customAiInstructions: (args as { custom_ai_instructions: string })
						.custom_ai_instructions,
				};
			}
			if (command === "get_feature_flags") {
				return { cloudAgents: false, cloudAgentsAvailable: false };
			}
			return { telemetryOptOut: false, autoUpdateEnabled: true };
		});

		await act(async () => {
			root.render(
				<SettingsView onNavigateSection={vi.fn()} section="General" />,
			);
		});
		const textarea = container.querySelector<HTMLTextAreaElement>(
			'textarea[aria-label="Custom AI instructions"]',
		);
		await vi.waitFor(() =>
			expect(textarea?.value).toBe("Always show the plan."),
		);

		await act(async () => {
			const setter = Object.getOwnPropertyDescriptor(
				HTMLTextAreaElement.prototype,
				"value",
			)?.set;
			setter?.call(textarea, "Always show the plan and run focused tests.");
			textarea?.dispatchEvent(new Event("input", { bubbles: true }));
		});
		const saveButton = Array.from(
			container.querySelectorAll<HTMLButtonElement>("button"),
		).find((button) => button.textContent?.includes("Save instructions"));
		expect(saveButton?.disabled).toBe(false);
		await act(async () => saveButton?.click());

		expect(invoke).toHaveBeenCalledWith("set_custom_ai_instructions", {
			custom_ai_instructions: "Always show the plan and run focused tests.",
		});
		await vi.waitFor(() =>
			expect(container.textContent).toContain("Saved permanently"),
		);
	});
});

describe("SettingsView diagnostics", () => {
	it("renders a sanitized health report without paths, URLs, or browser content", async () => {
		invoke.mockImplementation(async (command: string) => {
			if (command === "get_process_context") {
				return {
					appVersion: "0.0.34",
					platform: "win32",
					activeEnvironmentId: "local",
					runningSessionCount: 2,
					hub: { status: "connected", url: "ws://secret-local-url" },
					workspaceRoot: "C:/private/project",
				};
			}
			if (command === "get_global_settings") {
				return { permissionProfile: "full-access" };
			}
			if (command === "get_browser_state") {
				return { sessions: [{ url: "https://private.example/account" }] };
			}
			if (command === "get_computer_use_state") return { items: [] };
			if (command === "get_command_latency_baseline") {
				return { decision: { status: "collecting" }, workerEnabled: false };
			}
			return {};
		});

		await act(async () => {
			root.render(
				<SettingsView onNavigateSection={vi.fn()} section="Diagnostics" />,
			);
			await Promise.resolve();
			await Promise.resolve();
		});

		expect(container.textContent).toContain("Diagnostics");
		expect(container.textContent).toContain("connected");
		expect(container.textContent).toContain("Full access");
		expect(container.textContent).toContain("Browser sessions1");
		expect(container.textContent).not.toContain("private.example");
		expect(container.textContent).not.toContain("C:/private/project");
		expect(container.textContent).not.toContain("secret-local-url");
	});
});
