// @vitest-environment jsdom
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { desktopClient } from "@/lib/desktop-client";
import { ApkIncidentWorkspace } from "./apk-incident-workspace";

let container: HTMLDivElement, root: Root;
beforeEach(() => {
	Object.assign(globalThis, { IS_REACT_ACT_ENVIRONMENT: true });
	container = document.createElement("div");
	document.body.appendChild(container);
	root = createRoot(container);
});
afterEach(async () => {
	await act(async () => root.unmount());
	container.remove();
	vi.restoreAllMocks();
});
async function click(text: string) {
	const button = Array.from(container.querySelectorAll("button")).find((b) =>
		b.textContent?.includes(text),
	);
	expect(button).toBeDefined();
	await act(async () => {
		button?.dispatchEvent(new MouseEvent("click", { bubbles: true }));
		await Promise.resolve();
	});
}
const plan = {
	id: "plan-id",
	kind: "device",
	requestHash: "hash",
	requirements: ["authorized-target", "sensitive-device-logs"],
	request: { operation: "observe_apk" },
};
it("never starts from opening/refreshing and requires individual approvals", async () => {
	const invoke = vi
		.spyOn(desktopClient, "invoke")
		.mockImplementation(async (command) => {
			if (command === "prepare_apk_incident") return plan as never;
			if (command === "approve_analysis_task")
				return { executionToken: "one-shot" } as never;
			if (command === "start_apk_incident") return { id: "case-id" } as never;
			if (command === "get_apk_incident")
				return {
					id: "case-id",
					status: "completed",
					revision: 1,
					stage: "capture-completed",
					request: {},
				} as never;
			return [] as never;
		});
	await act(async () =>
		root.render(
			<ApkIncidentWorkspace cwd={"C:\\work"} environmentId="local" />,
		),
	);
	expect(invoke.mock.calls.map((c) => c[0])).toEqual(["list_apk_incidents"]);
	await click("Refresh saved cases");
	expect(invoke.mock.calls.some((c) => c[0] === "start_apk_incident")).toBe(
		false,
	);
	await click("Prepare hash-bound plan");
	const start = Array.from(container.querySelectorAll("button")).find((b) =>
		b.textContent?.includes("Approve and start once"),
	)!;
	expect(start.disabled).toBe(true);
	await act(async () => {
		for (const check of container.querySelectorAll<HTMLInputElement>(
			'input[type="checkbox"]',
		))
			check.click();
	});
	expect(start.disabled).toBe(false);
	await click("Approve and start once");
	expect(
		invoke.mock.calls.filter((c) => c[0] === "start_apk_incident"),
	).toHaveLength(1);
	expect(
		invoke.mock.calls.find((c) => c[0] === "start_apk_incident")?.[1],
	).toEqual(
		expect.objectContaining({
			cwd: "C:\\work",
			environmentId: "local",
			executionToken: "one-shot",
		}),
	);
});
it("ignores a stale plan after changing workspace", async () => {
	let resolvePlan!: (value: unknown) => void;
	const invoke = vi
		.spyOn(desktopClient, "invoke")
		.mockImplementation(async (command) =>
			command === "prepare_apk_incident"
				? ((await new Promise((res) => {
						resolvePlan = res;
					})) as never)
				: ([] as never),
		);
	await act(async () =>
		root.render(<ApkIncidentWorkspace cwd="first" environmentId="local" />),
	);
	await click("Prepare hash-bound plan");
	await act(async () =>
		root.render(<ApkIncidentWorkspace cwd="second" environmentId="local" />),
	);
	await act(async () => resolvePlan(plan));
	expect(container.textContent).not.toContain("Approve and start once");
	expect(invoke.mock.calls.some((c) => c[0] === "start_apk_incident")).toBe(
		false,
	);
});
it("never retries an ambiguous accepted submission", async () => {
	const invoke = vi
		.spyOn(desktopClient, "invoke")
		.mockImplementation(async (command) => {
			if (command === "prepare_apk_incident")
				return { ...plan, requirements: [] } as never;
			if (command === "approve_analysis_task")
				return { executionToken: "one-shot" } as never;
			if (command === "start_apk_incident")
				throw new Error("Response lost after acceptance");
			return [] as never;
		});
	await act(async () => root.render(<ApkIncidentWorkspace cwd="work" />));
	await click("Prepare hash-bound plan");
	await click("Approve and start once");
	await click("Refresh saved cases");
	expect(
		invoke.mock.calls.filter((c) => c[0] === "start_apk_incident"),
	).toHaveLength(1);
	expect(container.textContent).toContain("Response lost after acceptance");
});
