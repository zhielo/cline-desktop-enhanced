import { describe, expect, it } from "vitest";
import type { ChatMessage } from "@/lib/chat-schema";
import { processContext } from "./process-context";
const message = (ownerSessionId = "s"): ChatMessage => ({
	id: "m",
	sessionId: "s",
	role: "tool",
	createdAt: 1,
	content: JSON.stringify({
		toolName: "process_session",
		input: {
			action: "read",
			process_id: "owned-process",
			input: "private stdin",
		},
		result: {
			session: {
				processId: "owned-process",
				ownerSessionId,
				executable: "python",
				cwd: "C:/work",
				args: ["private"],
				env: { secret: "private" },
			},
		},
	}),
});
describe("recorded process ownership context", () => {
	it("associates follow-ups by process ID while omitting argv, environment, stdin and current liveness", () => {
		expect(processContext(message())).toEqual({
			action: "read",
			id: "owned-process",
			cwd: "[LOCAL PATH]",
			executable: "python",
			ownerConfirmed: true,
		});
		expect(JSON.stringify(processContext(message()))).not.toContain("private");
	});
	it("does not disclose another session's returned command or directory", () => {
		expect(processContext(message("other"))).toEqual({
			action: "read",
			id: "owned-process",
			cwd: null,
			executable: null,
			ownerConfirmed: false,
		});
	});
	it("does not treat malformed or non-process payloads as process context", () => {
		expect(processContext({ ...message(), content: "not json" })).toBeNull();
		expect(
			processContext({
				...message(),
				content: JSON.stringify({ toolName: "read_files" }),
			}),
		).toBeNull();
	});
});
