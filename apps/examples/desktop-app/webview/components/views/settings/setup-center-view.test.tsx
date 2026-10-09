// @vitest-environment jsdom
import { act } from "react";
import { createRoot } from "react-dom/client";
import { expect, it, vi } from "vitest";

const calls = vi.hoisted(() => vi.fn());
vi.mock("@/lib/desktop-client", () => ({ desktopClient: { invoke: calls } }));

import { SetupCenter } from "./setup-center-view";

it("reads status only on open and installs only after explicit notice acceptance", async () => {
	Object.assign(globalThis, { IS_REACT_ACT_ENVIRONMENT: true });
	calls.mockResolvedValue({
		preferences: null,
		fullStatus: "Setup needed",
		features: [
			{
				id: "qbdi",
				label: "qbdi",
				status: "Setup needed",
				reason: "Owned execution required",
			},
		],
		packs: [],
		limitations: [],
	});
	const element = document.createElement("div");
	document.body.append(element);
	const root = createRoot(element);
	const confirm = vi.spyOn(window, "confirm").mockReturnValue(false);
	try {
		await act(async () => root.render(<SetupCenter />));
		expect(calls).toHaveBeenCalledTimes(1);
		expect(calls.mock.calls[0][0]).toBe("setup_center_status");
		const button = [...element.querySelectorAll("button")].find(
			(b) => b.textContent === "Install all supported components",
		)!;
		await act(async () => button.click());
		expect(calls).toHaveBeenCalledTimes(1);
		confirm.mockReturnValue(true);
		await act(async () => button.click());
		expect(confirm.mock.calls.at(-1)?.[0]).toContain("reviewed and accept");
		expect(calls).toHaveBeenCalledWith(
			"setup_center_install_full",
			{
				environmentId: "local",
				confirmed: true,
				acceptedPlatformToolsLicense: true,
				background: true,
			},
			{ timeoutMs: 15000 },
		);
		expect(element.textContent).toContain("qbdi: Setup needed");
	} finally {
		confirm.mockRestore();
		await act(async () => root.unmount());
		element.remove();
		calls.mockReset();
	}
});

it("saves the selected IDA folder and requests only the explicitly approved ARM64 fixture", async () => {
	Object.assign(globalThis, { IS_REACT_ACT_ENVIRONMENT: true });
	calls.mockReset();
	const status = {
		preferences: {
			schemaVersion: 1,
			idaHome: "C:\\Licensed IDA",
			adbPath: "",
			deviceSerial: "",
			deviceKind: "physical",
			workerEndpoint: "",
			workerPublicKey: "",
			acceptedPlatformToolsLicense: false,
		},
		features: [],
		packs: [],
		limitations: [],
		fullStatus: "Setup needed",
		licensedArchitectures: [],
		desktopBuild: { version: "0.3.0", sourceCommit: "owned-build" },
	};
	calls.mockResolvedValue(status);
	const element = document.createElement("div");
	document.body.append(element);
	const root = createRoot(element);
	const confirm = vi.spyOn(window, "confirm").mockReturnValue(true);
	try {
		await act(async () => root.render(<SetupCenter />));
		const select = [...element.querySelectorAll("select")].find((e) =>
			e.closest("label")?.textContent?.includes("IDA acceptance processor"),
		)!;
		await act(async () => {
			select.value = "arm64";
			select.dispatchEvent(new Event("change", { bubbles: true }));
		});
		const button = [...element.querySelectorAll("button")].find(
			(e) => e.textContent === "Test IDA integration (optional)",
		)!;
		await act(async () => button.click());
		expect(calls).toHaveBeenCalledWith(
			"setup_center_test_ida",
			{
				environmentId: "local",
				confirmed: true,
				authorizedLicense: true,
				architecture: "arm64",
				idaHome: status.preferences.idaHome,
				background: true,
			},
			{ timeoutMs: 15000 },
		);
		expect(confirm.mock.calls.at(-1)?.[0]).toContain("fixed owned arm64");
		expect(element.textContent).toContain("owned-build");
		expect(element.textContent).toContain(
			"optional; direct IDA analysis remains available",
		);
	} finally {
		await act(async () => root.unmount());
		element.remove();
		confirm.mockRestore();
		calls.mockReset();
	}
});

it("reattaches a running job after navigation and polls read-only without replaying installation", async () => {
	Object.assign(globalThis, { IS_REACT_ACT_ENVIRONMENT: true });
	calls.mockReset();
	vi.useFakeTimers();
	localStorage.clear();
	const job = {
		id: "12345678-1234-1234-1234-123456789012",
		command: "setup_center_install_full",
		status: "running",
		phase: "Verifying immutable full packs",
		startedAt: new Date().toISOString(),
	};
	let terminal = false;
	const status = {
		preferences: null,
		features: [],
		packs: [],
		limitations: [],
		fullStatus: "Setup needed",
		setupJob: job,
	};
	calls.mockImplementation(async (command: string) =>
		command === "setup_center_job_status"
			? {
					job: {
						...job,
						status: terminal ? "completed" : "running",
						phase: terminal ? "Completed" : "Testing owned fixtures",
					},
				}
			: {
					...status,
					setupJob: { ...job, status: terminal ? "completed" : "running" },
					fullStatus: terminal ? "Ready" : "Setup needed",
				},
	);
	const element = document.createElement("div");
	document.body.append(element);
	let root = createRoot(element);
	try {
		await act(async () => root.render(<SetupCenter />));
		expect(element.textContent).toContain(job.id);
		expect(element.textContent).toContain("Verifying immutable");
		await act(async () => vi.advanceTimersByTimeAsync(600));
		expect(element.textContent).toContain("Testing owned fixtures");
		await act(async () => root.unmount());
		root = createRoot(element);
		await act(async () => root.render(<SetupCenter />));
		terminal = true;
		await act(async () => vi.advanceTimersByTimeAsync(600));
		expect(element.textContent).toContain("Ready");
		expect(
			calls.mock.calls.every(([command]) =>
				["setup_center_status", "setup_center_job_status"].includes(command),
			),
		).toBe(true);
	} finally {
		await act(async () => root.unmount());
		element.remove();
		calls.mockReset();
		vi.useRealTimers();
		localStorage.clear();
	}
});
it("distinguishes request timeout from background installation failure and never resubmits", async () => {
	Object.assign(globalThis, { IS_REACT_ACT_ENVIRONMENT: true });
	calls.mockReset();
	vi.useFakeTimers();
	localStorage.clear();
	const status = {
		preferences: null,
		features: [],
		packs: [],
		limitations: [],
		fullStatus: "Setup needed",
	};
	calls.mockImplementation(async (command: string) => {
		if (command === "setup_center_install_full")
			throw new Error(
				"Desktop command timed out waiting for setup_center_install_full",
			);
		if (command === "setup_center_job_status")
			return {
				job: {
					id: "12345678-1234-1234-1234-123456789012",
					command: "setup_center_install_full",
					status: "running",
					phase: "Testing owned engines",
					startedAt: new Date().toISOString(),
				},
			};
		return status;
	});
	const element = document.createElement("div");
	document.body.append(element);
	const root = createRoot(element),
		confirm = vi.spyOn(window, "confirm").mockReturnValue(true);
	try {
		await act(async () => root.render(<SetupCenter />));
		const button = [...element.querySelectorAll("button")].find(
			(b) => b.textContent === "Install all supported components",
		)!;
		await act(async () => button.click());
		expect(element.textContent).toContain("installation may still be running");
		await act(async () => vi.advanceTimersByTimeAsync(600));
		expect(element.textContent).toContain("Testing owned engines");
		expect(
			calls.mock.calls.filter(
				([command]) => command === "setup_center_install_full",
			),
		).toHaveLength(1);
	} finally {
		await act(async () => root.unmount());
		element.remove();
		confirm.mockRestore();
		calls.mockReset();
		vi.useRealTimers();
		localStorage.clear();
	}
});
it("preserves processor choice on remount and saves IDA without running the optional test", async () => {
	Object.assign(globalThis, { IS_REACT_ACT_ENVIRONMENT: true });
	calls.mockReset();
	localStorage.clear();
	const status = {
		preferences: {
			schemaVersion: 1,
			idaHome: "C:\\Owned IDA",
			adbPath: "",
			deviceSerial: "",
			deviceKind: "physical",
			workerEndpoint: "",
			workerPublicKey: "",
			acceptedPlatformToolsLicense: false,
		},
		features: [],
		packs: [],
		limitations: [],
		fullStatus: "Setup needed",
	};
	calls.mockResolvedValue(status);
	const element = document.createElement("div");
	document.body.append(element);
	let root = createRoot(element);
	const confirm = vi.spyOn(window, "confirm").mockReturnValue(true);
	try {
		await act(async () => root.render(<SetupCenter />));
		let select = element.querySelector(
			'select[aria-label="IDA acceptance processor"]',
		) as HTMLSelectElement;
		await act(async () => {
			select.value = "arm64";
			select.dispatchEvent(new Event("change", { bubbles: true }));
		});
		await act(async () => root.unmount());
		root = createRoot(element);
		await act(async () => root.render(<SetupCenter />));
		select = element.querySelector(
			'select[aria-label="IDA acceptance processor"]',
		) as HTMLSelectElement;
		expect(select.value).toBe("arm64");
		await act(async () =>
			[...element.querySelectorAll("button")]
				.find((b) => b.textContent === "Save IDA installation")!
				.click(),
		);
		expect(calls).toHaveBeenCalledWith(
			"setup_center_save_ida",
			{
				environmentId: "local",
				confirmed: true,
				idaHome: status.preferences.idaHome,
			},
			{ timeoutMs: 300000 },
		);
		expect(
			calls.mock.calls.some(([command]) => command === "setup_center_test_ida"),
		).toBe(false);
	} finally {
		await act(async () => root.unmount());
		element.remove();
		confirm.mockRestore();
		calls.mockReset();
		localStorage.clear();
	}
});
