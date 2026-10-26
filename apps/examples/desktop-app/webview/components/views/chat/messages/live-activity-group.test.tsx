// @vitest-environment jsdom
import { act } from "react";
import { createRoot } from "react-dom/client";
import { describe, expect, it } from "vitest";
import type { ChatMessage } from "@/lib/chat-schema";
import { ActivityPresentationProvider } from "../activity-presentation";
import { LiveActivityGroup, splitActivity } from "./live-activity-group";
import type { ChatRenderItem } from "./group-messages";
const tool = (
	id: string,
	result: unknown = {},
	name = "read_files",
): ChatMessage => ({
	id,
	sessionId: "s",
	role: "tool",
	content: JSON.stringify({
		toolName: name,
		input: { paths: ["a.ts"] },
		result,
	}),
	createdAt: 1,
	meta: { toolName: name, toolCallId: id },
});
const ids = (items: ChatRenderItem[]) =>
	items.flatMap((item) =>
		item.type === "tools" ? item.messages.map((message) => message.id) : [],
	);
describe("compact activity safety", () => {
	it("keeps host-bound failures, blockers, native errors, unresolved tools and deliverables discoverable", () => {
		const failed = tool("failed");
		failed.meta!.taskEvent = {
			type: "tool.completed",
			toolCallId: "failed",
			toolName: "read_files",
			observation: {
				version: "task-observation/v1",
				id: "receipt",
				sessionId: "s",
				toolCallId: "failed",
				toolName: "read_files",
				source: "host-tool",
				execution: "finished",
				outcome: "failed",
				recordedAtMs: 2,
			},
		} satisfies NonNullable<NonNullable<ChatMessage["meta"]>["taskEvent"]>;
		const missing = tool("missing", null);
		const native = tool(
			"native",
			{ engine: "ida", succeeded: false, timedOut: true },
			"reverse_engineer",
		);
		const final = tool("final", {}, "submit_and_exit");
		const parts = splitActivity([
			{
				type: "tools",
				messages: [
					tool("quiet"),
					failed,
					tool("blocked", { outcome: "blocked" }),
					missing,
					native,
					final,
				],
			},
		]);
		expect(ids(parts.routine)).toEqual(["quiet"]);
		expect(ids(parts.attention)).toEqual([
			"failed",
			"blocked",
			"missing",
			"native",
			"final",
		]);
	});
	it("does not bind another session's receipt to a routine action", () => {
		const other = tool("other");
		other.meta!.taskEvent = {
			type: "tool.completed",
			toolCallId: "other",
			toolName: "read_files",
			observation: {
				version: "task-observation/v1",
				id: "receipt",
				sessionId: "foreign",
				toolCallId: "other",
				toolName: "read_files",
				source: "host-tool",
				execution: "finished",
				outcome: "failed",
				recordedAtMs: 2,
			},
		} satisfies NonNullable<NonNullable<ChatMessage["meta"]>["taskEvent"]>;
		expect(
			ids(
				splitActivity([{ type: "tools", messages: [other, tool("last")] }])
					.routine,
			),
		).toEqual(["other"]);
	});
	it("lazily mounts routine rows, preserves manual state by session and leaves interrupted work visible", async () => {
		Object.assign(globalThis, { IS_REACT_ACT_ENVIRONMENT: true });
		const container = document.createElement("div");
		document.body.append(container);
		const root = createRoot(container);
		const items: ChatRenderItem[] = [
			{
				type: "tools",
				messages: Array.from({ length: 1000 }, (_, i) => tool(String(i))),
			},
		];
		const renderItem = (item: ChatRenderItem) =>
			item.type === "tools" ? (
				<div key={item.messages[0].id}>
					{item.messages.map((message) => (
						<p key={message.id}>{message.id}</p>
					))}
				</div>
			) : null;
		const render = async (
			sessionId: string,
			status: "running" | "cancelled" = "running",
			fullActivity = false,
		) =>
			act(async () =>
				root.render(
					<ActivityPresentationProvider>
						<LiveActivityGroup
							id="run"
							sessionId={sessionId}
							items={items}
							status={status}
							fullActivity={fullActivity}
							renderItem={renderItem}
						/>
					</ActivityPresentationProvider>,
				),
			);
		try {
			await render("a");
			expect(container.querySelectorAll("p")).toHaveLength(1);
			await act(async () => container.querySelector("button")!.click());
			expect(container.querySelectorAll("p")).toHaveLength(1000);
			await render("b");
			expect(container.querySelectorAll("p")).toHaveLength(1);
			await render("a");
			expect(container.querySelectorAll("p")).toHaveLength(1000);
			await act(async () => container.querySelector("button")!.click());
			await render("a");
			expect(container.querySelectorAll("p")).toHaveLength(1);
			await render("a", "running", true);
			expect(container.querySelectorAll("p")).toHaveLength(1000);
			await render("a", "cancelled");
			expect(container.querySelectorAll("p")).toHaveLength(1000);
		} finally {
			await act(async () => root.unmount());
			container.remove();
		}
	});
});
