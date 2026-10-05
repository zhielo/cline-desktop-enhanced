import { timingSafeEqual } from "node:crypto";

// Per-process sidecar capability, not a Cline/provider account credential.
// Keep the existing query name for the native/dev endpoint handoff.
const TOKEN_PARAM = "approval_token";
const MAX_TOKEN_BYTES = 512;
function matches(candidate: string | null, expected: string): boolean {
	if (
		!candidate ||
		!expected ||
		candidate.length > MAX_TOKEN_BYTES ||
		expected.length > MAX_TOKEN_BYTES
	)
		return false;
	const actual = Buffer.from(candidate);
	const trusted = Buffer.from(expected);
	return (
		actual.length <= MAX_TOKEN_BYTES &&
		trusted.length <= MAX_TOKEN_BYTES &&
		actual.length === trusted.length &&
		timingSafeEqual(actual, trusted)
	);
}
export function hasSidecarAuthentication(
	req: Request,
	expected: string,
	allowQuery = false,
): boolean {
	const values = new URL(req.url).searchParams.getAll(TOKEN_PARAM);
	const header = req.headers.get("authorization");
	// Reject conflicting credential sources, duplicates and an empty configuration.
	if (!expected || values.length > 1 || (header !== null && values.length > 0))
		return false;
	if (header !== null) {
		const bearer = /^Bearer ([^\s]+)$/i.exec(header);
		return matches(bearer?.[1] ?? null, expected);
	}
	return allowQuery && values.length === 1 && matches(values[0], expected);
}
