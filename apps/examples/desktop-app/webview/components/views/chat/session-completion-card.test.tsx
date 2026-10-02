// @vitest-environment jsdom

import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { desktopClient } from "@/lib/desktop-client";
import { SessionCompletionCard } from "./session-completion-card";

let container: HTMLDivElement;
let root: Root;

beforeEach(() => {
	Object.assign(globalThis, { IS_REACT_ACT_ENVIRONMENT: true });
	container = document.createElement("div");
	document.body.appendChild(container);
	root = createRoot(container);
	Object.defineProperty(navigator, "clipboard", {
		configurable: true,
		value: { writeText: vi.fn().mockResolvedValue(undefined) },
	});
});

afterEach(async () => {
	await act(async () => root.unmount());
	container.remove();
	vi.restoreAllMocks();
});

async function click(element: Element) {
	await act(async () => {
		element.dispatchEvent(
			new MouseEvent("click", { bubbles: true, cancelable: true }),
		);
		await Promise.resolve();
	});
}

describe("SessionCompletionCard", () => {
	it("opens a changed file and exposes the diff review action", async () => {
		const invoke = vi
			.spyOn(desktopClient, "invoke")
			.mockResolvedValue({ path: "src/app.ts", editor: "code" });
		const onOpenDiff = vi.fn();
		await act(async () => {
			root.render(
				<SessionCompletionCard
					cwd="C:\\work\\project"
					environmentId="local"
					fileDiffs={[
						{ path: "src/app.ts", additions: 12, deletions: 3, hunks: [] },
					]}
					onOpenDiff={onOpenDiff}
					status="completed"
					tools={8}
					turns={2}
				/>,
			);
		});

		const fileButton = [...container.querySelectorAll("button")].find((button) =>
			button.textContent?.includes("src/app.ts"),
		);
		expect(fileButton).toBeDefined();
		await click(fileButton as HTMLButtonElement);
		expect(invoke).toHaveBeenCalledWith("open_file_in_editor", {
			environmentId: "local",
			path: "src/app.ts",
			cwd: "C:\\work\\project",
		});

		const reviewButton = [...container.querySelectorAll("button")].find(
			(button) => button.textContent?.trim() === "Review changes",
		);
		await click(reviewButton as HTMLButtonElement);
		expect(onOpenDiff).toHaveBeenCalledOnce();
	});
});
