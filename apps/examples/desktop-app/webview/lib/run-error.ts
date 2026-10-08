import {
	isCredentialFailure,
	resolveCredentialFailureHint,
} from "@/hooks/chat-session/helpers";

const HUB_RECOVERY_GUIDANCE =
	"Your saved chat is preserved. Wait for reconnection, reopen this session, then send a new message. The previous task is not automatically replayed.";

const TRANSIENT_HUB_DISCONNECT =
	/^Hub connection closed \(code=1006,\s*reason=Connection ended\)$/i;

const CAPABILITY_OWNER_DISCONNECT =
	/^Capability owner client .+ disconnected before request was resolved\.?$/i;
const DESKTOP_TRANSPORT_DISCONNECT =
	/^Desktop backend transport (?:closed|unavailable)/i;
// Only an idempotent fork caller may reconcile/retry these ambiguous replies.
// In particular, never classify provider 401s or arbitrary sends as recoverable.
const FORK_LIFECYCLE_TIMEOUT =
	/^(?:Desktop command timed out waiting for chat_session_command|Hub command session\.(?:create|restore) timed out after \d+ms(?: .*)?)$/i;

function normalizedFailureDetail(detail: string): string {
	const raw = detail.endsWith(` ${HUB_RECOVERY_GUIDANCE}`)
		? detail.slice(0, -HUB_RECOVERY_GUIDANCE.length - 1)
		: detail;
	return raw
		.trim()
		.replace(/^The run failed:\s*/i, "")
		.trim();
}

/** Strictly identifies the abnormal Hub close that can be reconciled safely. */
export function isTransientHubDisconnect(detail: string): boolean {
	return TRANSIENT_HUB_DISCONNECT.test(normalizedFailureDetail(detail));
}

export function isCapabilityOwnerDisconnect(detail: string): boolean {
	return CAPABILITY_OWNER_DISCONNECT.test(normalizedFailureDetail(detail));
}

export function isRecoverableForkTransportError(error: unknown): boolean {
	const detail = error instanceof Error ? error.message : String(error);
	const normalized = normalizedFailureDetail(detail);
	return (
		TRANSIENT_HUB_DISCONNECT.test(normalized) ||
		CAPABILITY_OWNER_DISCONNECT.test(normalized) ||
		DESKTOP_TRANSPORT_DISCONNECT.test(normalized) ||
		FORK_LIFECYCLE_TIMEOUT.test(normalized)
	);
}

/** Retry one idempotent fork after the desktop/Hub transport reconnects. */
export async function retryRecoverableFork<T>(
	operation: () => Promise<T>,
	delayMs = 750,
	reconcile?: () => Promise<T | undefined>,
): Promise<T> {
	try {
		return await operation();
	} catch (error) {
		if (!isRecoverableForkTransportError(error)) throw error;
		if (delayMs > 0) {
			await new Promise((resolve) => setTimeout(resolve, delayMs));
		}
		if (reconcile) {
			try {
				const recovered = await reconcile();
				if (recovered !== undefined) return recovered;
			} catch (reconcileError) {
				if (!isRecoverableForkTransportError(reconcileError)) {
					throw reconcileError;
				}
			}
		}
		return await operation();
	}
}

/** The same presentation for live failures and restored transcript errors. */
export function formatRunError(detail: string, providerId = ""): string {
	const description = detail.trim();
	if (isTransientHubDisconnect(description))
		return `The run failed: ${normalizedFailureDetail(description)} ${HUB_RECOVERY_GUIDANCE}`;
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
