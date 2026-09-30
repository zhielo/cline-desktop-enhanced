import {
	isCredentialFailure,
	resolveCredentialFailureHint,
} from "@/hooks/chat-session/helpers";

const TRANSIENT_HUB_DISCONNECT =
	/^Hub connection closed \(code=1006,\s*reason=Connection ended\)$/i;

/** Strictly identifies the abnormal Hub close that can be reconciled safely. */
export function isTransientHubDisconnect(detail: string): boolean {
	const normalized = detail
		.trim()
		.replace(/^The run failed:\s*/i, "")
		.trim();
	return TRANSIENT_HUB_DISCONNECT.test(normalized);
}

/** The same presentation for live failures and restored transcript errors. */
export function formatRunError(detail: string, providerId = ""): string {
	const description = detail.trim();
	const guidance = resolveCredentialFailureHint(providerId);
	const looksCredentialRelated =
		!description || isCredentialFailure(description);
	return [
		description
			? description.startsWith("The run failed")
				? description
				: `The run failed: ${description}`
			: "The run failed before a response was produced.",
		looksCredentialRelated && !description.includes(guidance) ? guidance : "",
	]
		.filter(Boolean)
		.join(" ");
}
