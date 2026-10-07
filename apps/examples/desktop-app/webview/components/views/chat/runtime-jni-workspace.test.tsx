// @vitest-environment jsdom
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { desktopClient } from "@/lib/desktop-client";
import { RuntimeJniWorkspace } from "./runtime-jni-workspace";

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
it("opening and refreshing only read saved plans and never execute or capture", async () => {
	const invoke = vi
		.spyOn(desktopClient, "invoke")
		.mockResolvedValue([] as never);
	await act(async () => root.render(<RuntimeJniWorkspace cwd="C:\work" />));
	await act(async () =>
		Array.from(host.querySelectorAll("button"))
			.find((b) => b.textContent === "Refresh completed JNI captures")!
			.click(),
	);
	expect(invoke.mock.calls.map((c) => c[0])).toEqual([
		"list_analysis_tasks",
		"list_analysis_tasks",
	]);
});
it("ignores a late evidence query when the workspace changes", async () => {
	let finish!: (v: unknown) => void;
	vi.spyOn(desktopClient, "invoke").mockImplementation(async (command) =>
		command === "query_runtime_jni"
			? ((await new Promise((r) => {
					finish = r;
				})) as never)
			: ([] as never),
	);
	await act(async () => root.render(<RuntimeJniWorkspace cwd="C:\old" />));
	await act(async () =>
		Array.from(host.querySelectorAll("button"))
			.find((b) => b.textContent === "Verify and query signed registrations")!
			.click(),
	);
	await act(async () => root.render(<RuntimeJniWorkspace cwd="C:\new" />));
	await act(async () => finish({ secret: "old-scope-result" }));
	expect(host.textContent).not.toContain("old-scope-result");
});
