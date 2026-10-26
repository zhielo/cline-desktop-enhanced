import type { ChatMessage } from "@/lib/chat-schema";
import {
	redactReportText,
	reportRecord,
} from "../../../../../shared/task-observation";
import { normalizeDisplayValue, parseToolPayload } from "./tool-summaries";

/** Recorded context only: never infer process liveness or expose argv/env/stdin. */
export function processContext(message: ChatMessage) {
	const payload = parseToolPayload(message.content);
	if ((message.meta?.toolName ?? payload?.toolName) !== "process_session")
		return null;
	const input = reportRecord(normalizeDisplayValue(payload?.input));
	const result = reportRecord(normalizeDisplayValue(payload?.result));
	const snapshot = reportRecord(result?.session) ?? result;
	const owner = snapshot?.ownerSessionId;
	const owned = typeof owner === "string" && owner === message.sessionId;
	const action = [
		"start",
		"list",
		"read",
		"write",
		"resize",
		"signal",
		"close",
	].includes(String(input?.action))
		? String(input?.action)
		: "operation";
	const id =
		typeof input?.process_id === "string"
			? input.process_id
			: owned && typeof snapshot?.processId === "string"
				? snapshot.processId
				: null;
	const cwd =
		owned && typeof snapshot?.cwd === "string"
			? redactReportText(snapshot.cwd).slice(0, 500)
			: null;
	const executable =
		owned && typeof snapshot?.executable === "string"
			? redactReportText(snapshot.executable).slice(0, 200)
			: null;
	return {
		action,
		id: id ? redactReportText(id).slice(0, 300) : null,
		cwd,
		executable,
		ownerConfirmed: owned,
	};
}
