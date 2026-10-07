// @vitest-environment jsdom
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { desktopClient } from "@/lib/desktop-client";
import { ExecutionWorkspace } from "./execution-workspace";

let host: HTMLDivElement, root: Root;
beforeEach(() => {
	Object.assign(globalThis, { IS_REACT_ACT_ENVIRONMENT: true });
	host = document.createElement("div");
	document.body.appendChild(host);
	root = createRoot(host);
});
afterEach(async () => {
	await act(async () => root.unmount());
	host.remove();
	vi.restoreAllMocks();
});
async function click(label: string) {
	const b = Array.from(host.querySelectorAll("button")).find(
		(b) => b.textContent === label,
	)!;
	expect(b).toBeDefined();
	await act(async () => {
		b.click();
		await Promise.resolve();
	});
}
const plan = {
	id: "plan",
	requestHash: "exact",
	requirements: ["trusted-host-work", "side-effect-review"],
	request: { operation: "execution_pipeline" },
};
it("opening and refresh never execute; each requirement must be acknowledged", async () => {
	const invoke = vi
		.spyOn(desktopClient, "invoke")
		.mockImplementation(async (command) =>
			command === "prepare_execution_pipeline"
				? (plan as never)
				: command === "approve_analysis_task"
					? ({ executionToken: "one-shot" } as never)
					: command === "start_execution_pipeline"
						? ({ id: "receipt" } as never)
						: command === "get_execution_receipt"
							? ({ id: "receipt", status: "completed" } as never)
							: ([] as never),
		);
	await act(async () =>
		root.render(<ExecutionWorkspace cwd="C:\work" environmentId="local" />),
	);
	await click("Refresh receipts");
	expect(
		invoke.mock.calls.some((c) => c[0] === "start_execution_pipeline"),
	).toBe(false);
	await click("Prepare exact task");
	const b = Array.from(host.querySelectorAll("button")).find(
		(b) => b.textContent === "Approve and start once",
	)!;
	expect(b.disabled).toBe(true);
	await act(async () => {
		for (const c of host.querySelectorAll<HTMLInputElement>(
			"input[type=checkbox]",
		))
			c.click();
	});
	await click("Approve and start once");
	expect(
		invoke.mock.calls.filter((c) => c[0] === "start_execution_pipeline"),
	).toHaveLength(1);
	expect(
		invoke.mock.calls.find((c) => c[0] === "start_execution_pipeline")?.[1],
	).toMatchObject({
		cwd: "C:\\work",
		environmentId: "local",
		executionToken: "one-shot",
	});
});
it("drops stale prepared plans when the workspace changes", async () => {
	let finish!: (v: unknown) => void;
	const invoke = vi
		.spyOn(desktopClient, "invoke")
		.mockImplementation(async (command) =>
			command === "prepare_execution_pipeline"
				? ((await new Promise((r) => {
						finish = r;
					})) as never)
				: ([] as never),
		);
	await act(async () => root.render(<ExecutionWorkspace cwd="C:\old" />));
	await click("Prepare exact task");
	await act(async () => root.render(<ExecutionWorkspace cwd="C:\new" />));
	await act(async () => finish(plan));
	expect(host.textContent).not.toContain("Approve and start once");
	expect(
		invoke.mock.calls.some((c) => c[0] === "start_execution_pipeline"),
	).toBe(false);
});
