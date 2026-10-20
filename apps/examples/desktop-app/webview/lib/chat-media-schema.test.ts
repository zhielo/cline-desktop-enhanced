import { it, expect } from "vitest";
import { ChatMessageSchema, ChatMessageMediaSchema } from "./chat-schema";
it.each([
	"image",
	"audio",
	"video",
	"file",
])("validates %s media across schema majors and JSON history", (modality) => {
	const media = {
		id: "m",
		modality,
		mediaType: modality === "file" ? "application/pdf" : `${modality}/test`,
		source: { type: "url", url: "https://example.com/owned" },
	};
	const message = {
		id: "1",
		sessionId: "s",
		role: "assistant",
		content: "",
		createdAt: 1,
		media: [media],
	};
	expect(ChatMessageSchema.safeParse(message).success).toBe(true);
	expect(
		ChatMessageSchema.safeParse(JSON.parse(JSON.stringify(message))).success,
	).toBe(true);
});
it("returns validation failures, not exceptions, for invalid media", () => {
	for (const media of [
		null,
		{},
		{
			id: "m",
			modality: "image",
			mediaType: "audio/wav",
			source: { type: "base64", data: "x" },
		},
		{
			id: "m",
			modality: "image",
			mediaType: "image/png",
			source: { type: "url", url: "file:///secret" },
		},
	]) {
		expect(() => ChatMessageMediaSchema.safeParse(media)).not.toThrow();
		expect(ChatMessageMediaSchema.safeParse(media).success).toBe(false);
	}
});
