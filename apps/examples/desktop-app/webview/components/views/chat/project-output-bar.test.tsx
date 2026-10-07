// @vitest-environment jsdom
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { beforeEach, afterEach, expect, it, vi } from "vitest";
import { desktopClient } from "@/lib/desktop-client";
import { ProjectOutputBar } from "./project-output-bar";
let host: HTMLDivElement, root: Root;
beforeEach(() => {
	Object.assign(globalThis, { IS_REACT_ACT_ENVIRONMENT: true });
	host = document.createElement("div");
	document.body.append(host);
	root = createRoot(host);
});
afterEach(async () => {
	await act(async () => root.unmount());
	host.remove();
	vi.restoreAllMocks();
});
const location = {
	root: "C:\\Cline-Outputs",
	projectDirectory: "C:\\Cline-Outputs\\owned-0123456789abcdef",
};
it("displays the specific folder without creating/opening it until an explicit click", async () => {
	const invoke = vi
		.spyOn(desktopClient, "invoke")
		.mockImplementation(async () => location as never);
	await act(async () =>
		root.render(
			<ProjectOutputBar cwd={"C:\\work\\owned"} environmentId="local" />,
		),
	);
	expect(host.textContent).toContain(location.projectDirectory);
	expect(invoke.mock.calls.map((c) => c[0])).toEqual([
		"get_project_output_location",
	]);
	const button = Array.from(host.querySelectorAll("button")).find(
		(b) => b.textContent === "Open outputs",
	);
	expect(button).toBeDefined();
	await act(async () => button?.click());
	expect(invoke).toHaveBeenCalledWith("open_project_output_folder", {
		cwd: "C:\\work\\owned",
		environmentId: "local",
	});
});
it("never routes SSH output to the local fixed folder", async () => {
	const invoke = vi
		.spyOn(desktopClient, "invoke")
		.mockResolvedValue(null as never);
	await act(async () =>
		root.render(
			<ProjectOutputBar cwd={"/remote/project"} environmentId="ssh-owned" />,
		),
	);
	expect(invoke).not.toHaveBeenCalled();
	expect(host.textContent).toBe("");
});
it("shows permission failure without falling back to a different folder", async () => {
	const invoke = vi
		.spyOn(desktopClient, "invoke")
		.mockImplementation(async (c) => {
			if (c === "get_project_output_location") return location as never;
			throw new Error("EACCES: C:\\Cline-Outputs");
		});
	await act(async () =>
		root.render(
			<ProjectOutputBar cwd={"C:\\work\\owned"} environmentId="local" />,
		),
	);
	await act(async () =>
		Array.from(host.querySelectorAll("button"))
			.find((b) => b.textContent === "Open outputs")
			?.click(),
	);
	expect(host.querySelector('[role="alert"]')?.textContent).toContain("EACCES");
	expect(
		invoke.mock.calls.filter((c) => c[0] === "open_project_output_folder"),
	).toHaveLength(1);
});
it("ignores a delayed previous-project location after switching projects", async () => {
	let finish!: (v: typeof location) => void;
	const previous = new Promise<typeof location>((r) => {
		finish = r;
	});
	vi.spyOn(desktopClient, "invoke").mockImplementation(async (_c, args) =>
		args?.cwd === "C:\\one"
			? ((await previous) as never)
			: ({
					root: location.root,
					projectDirectory: "C:\\Cline-Outputs\\two-0123456789abcdef",
				} as never),
	);
	await act(async () =>
		root.render(<ProjectOutputBar cwd={"C:\\one"} environmentId="local" />),
	);
	await act(async () =>
		root.render(<ProjectOutputBar cwd={"C:\\two"} environmentId="local" />),
	);
	await act(async () => finish(location));
	expect(host.textContent).toContain("two-");
	expect(host.textContent).not.toContain("owned-");
});
