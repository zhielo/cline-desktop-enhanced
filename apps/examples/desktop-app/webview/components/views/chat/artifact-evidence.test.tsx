// @vitest-environment jsdom
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { desktopClient } from "@/lib/desktop-client";
import { ArtifactContextMenu } from "./artifact-context-menu";

// Model menu selection without depending on browser context-menu positioning.
vi.mock("@/components/ui/context-menu", () => ({
	ContextMenu: ({ children }: { children: React.ReactNode }) => (
		<div>{children}</div>
	),
	ContextMenuTrigger: ({ children }: { children: React.ReactNode }) => (
		<div>{children}</div>
	),
	ContextMenuContent: ({ children }: { children: React.ReactNode }) => (
		<div>{children}</div>
	),
	ContextMenuItem: ({
		children,
		onSelect,
	}: {
		children: React.ReactNode;
		onSelect: () => void;
	}) => (
		<button type="button" onClick={onSelect}>
			{children}
		</button>
	),
	ContextMenuSeparator: () => null,
}));
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
it("requests an explicit member preview bound to originating workspace and container hash", async () => {
	const hash = "a".repeat(64),
		invoke = vi
			.spyOn(desktopClient, "invoke")
			.mockImplementation(async (command) =>
				command === "inspect_artifact_evidence"
					? ({
							path: "C:\\work\\report.xlsx",
							workspace: "C:\\work",
							sha256: hash,
							size: 12,
							classification: "archive-container",
							members: [
								{ name: "xl/worksheets/sheet1.xml", bytes: 4, safe: true },
							],
						} as never)
					: ({
							path: "C:\\work\\report.xlsx",
							kind: "text",
							size: 4,
							content: "test",
						} as never),
			);
	await act(async () =>
		root.render(
			<ArtifactContextMenu
				cwd={"C:\\work"}
				environmentId="local"
				path="report.xlsx"
				onOpen={() => {}}
			>
				<span>artifact</span>
			</ArtifactContextMenu>,
		),
	);
	await act(async () => {
		Array.from(container.querySelectorAll("button"))
			.find((b) => b.textContent?.includes("Inspect evidence / archive"))
			?.click();
	});
	expect(invoke.mock.calls).toHaveLength(1);
	const select = document.querySelector<HTMLSelectElement>(
		'select[aria-label="Archive member"]',
	)!;
	await act(async () => {
		select.value = "xl/worksheets/sheet1.xml";
		select.dispatchEvent(new Event("change", { bubbles: true }));
	});
	expect(invoke.mock.calls[1]).toEqual([
		"preview_archive_member",
		{
			path: "report.xlsx",
			cwd: "C:\\work",
			environmentId: "local",
			member: "xl/worksheets/sheet1.xml",
			expectedHash: hash,
		},
	]);
	expect(
		invoke.mock.calls.some((c) =>
			["open_artifact", "reveal_artifact_in_folder"].includes(c[0]),
		),
	).toBe(false);
});
