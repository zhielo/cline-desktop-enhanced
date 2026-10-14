// @vitest-environment jsdom
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { beforeEach, afterEach, it, expect, vi } from "vitest";
import { DraftRecoveryControl } from "./draft-recovery-control";
import {
	draftRecoveryKey,
	readRecoverableDraft,
	saveRecoverableDraft,
} from "@/lib/draft-recovery";
let el: HTMLDivElement, root: Root;
const restore = vi.fn();
const key = (s: string) => draftRecoveryKey("local", "/owned", s);
beforeEach(() => {
	Object.assign(globalThis, { IS_REACT_ACT_ENVIRONMENT: true });
	localStorage.clear();
	restore.mockReset();
	vi.useFakeTimers();
	el = document.createElement("div");
	document.body.append(el);
	root = createRoot(el);
	vi.spyOn(window, "confirm").mockReturnValue(true);
});
afterEach(async () => {
	await act(async () => root.unmount());
	el.remove();
	vi.useRealTimers();
	vi.restoreAllMocks();
});
const render = async (s: string, value: string) => {
	await act(async () =>
		root.render(
			<DraftRecoveryControl
				environmentId="local"
				workspace="/owned"
				sessionId={s}
				value={value}
				onRestore={restore}
			/>,
		),
	);
};
it("never restores/sends automatically or deletes an existing draft on empty mount", async () => {
	saveRecoverableDraft(localStorage, key("one"), "recover me");
	localStorage.setItem(`${key("one")}:enabled`, "true");
	await render("one", "");
	await act(async () => vi.advanceTimersByTime(1000));
	expect(readRecoverableDraft(localStorage, key("one"))).toBe("recover me");
	expect(restore).not.toHaveBeenCalled();
	await act(async () =>
		[...el.querySelectorAll("button")]
			.find((b) => b.textContent === "Recover saved draft")!
			.click(),
	);
	expect(restore).toHaveBeenCalledWith("recover me");
});
it("scope switching never writes the previous prompt into a different session", async () => {
	localStorage.setItem(`${key("one")}:enabled`, "true");
	localStorage.setItem(`${key("two")}:enabled`, "true");
	saveRecoverableDraft(localStorage, key("two"), "second draft");
	await render("one", "old prompt");
	await render("one", "edited old prompt");
	await render("two", "edited old prompt");
	await act(async () => vi.advanceTimersByTime(1000));
	expect(readRecoverableDraft(localStorage, key("two"))).toBe("second draft");
	await render("two", "new owned edit");
	await act(async () => vi.advanceTimersByTime(1000));
	expect(readRecoverableDraft(localStorage, key("two"))).toBe("new owned edit");
});
