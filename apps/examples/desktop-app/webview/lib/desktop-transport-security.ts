/** Redact sidecar capabilities before diagnostics; not a general secret scanner. */
export function redactDesktopTransportSecrets(
	value: string,
	knownToken?: string,
): string {
	const redacted = value
		.replace(/([?&]approval_token=)[^&\s"'<>]*/gi, "$1[redacted]")
		.replace(/\bBearer\s+[^\s"'<>]+/gi, "Bearer [redacted]");
	return knownToken ? redacted.split(knownToken).join("[redacted]") : redacted;
}
