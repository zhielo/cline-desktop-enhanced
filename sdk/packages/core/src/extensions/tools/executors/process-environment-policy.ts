const REDACTED = "[REDACTED]";
// Sensitive values are security data even when a test account or local
// integration uses an unusually short credential. Redacting a short value can
// reduce output fidelity, but leaking it would violate the host grant contract.
const MIN_EXACT_SECRET_LENGTH = 1;
const MAX_SYNTAX_CARRY_CHARS = 512;

const SENSITIVE_ENVIRONMENT_NAMES = new Set([
	"AWS_ACCESS_KEY_ID",
	"AWS_SECRET_ACCESS_KEY",
	"AWS_SESSION_TOKEN",
	"AZURE_CLIENT_SECRET",
	"DATABASE_URL",
	"GITHUB_TOKEN",
	"GITLAB_TOKEN",
	"GOOGLE_APPLICATION_CREDENTIALS",
	"NPM_TOKEN",
	"OTEL_EXPORTER_OTLP_HEADERS",
	"TELEMETRY_SERVICE_API_KEY",
]);

const SENSITIVE_ENVIRONMENT_SEGMENT =
	/(?:^|_)(?:ACCESS_TOKEN|API_KEY|AUTHORIZATION|CLIENT_SECRET|CREDENTIALS?|ID_TOKEN|JWT|PASSWORD|PRIVATE_KEY|REFRESH_TOKEN|SECRET|SIGNING_KEY|TOKEN)(?:_|$)/i;

const CREDENTIAL_URL_PATTERN =
	/\b([a-z][a-z0-9+.-]*:\/\/)([^/\s:@]+):([^/\s@]+)@/gi;
const AUTHORIZATION_PATTERN =
	/\b((?:proxy-)?authorization\s*[:=]\s*(?:basic|bearer)?\s*)[^\s,;"']+/gi;
const BEARER_PATTERN = /\b(bearer\s+)(?!\[redacted\])[a-z0-9._~+/-]+=*/gi;
const SECRET_ASSIGNMENT_PATTERN =
	/((?:["']?(?:access[_ -]?token|api[_ -]?key|authorization|client[_ -]?secret|credential|id[_ -]?token|password|private[_ -]?key|refresh[_ -]?token|secret|signing[_ -]?key|token)["']?)\s*[:=]\s*)(["']?)([^"'\s,;}]+)\2/gi;
const PRIVATE_KEY_PATTERN =
	/-----BEGIN [^-]*PRIVATE KEY-----[\s\S]*?-----END [^-]*PRIVATE KEY-----/g;
const WELL_KNOWN_TOKEN_PATTERNS = [
	/\bgh[pousr]_[A-Za-z0-9]{20,}\b/g,
	/\bgithub_pat_[A-Za-z0-9_]{20,}\b/g,
	/\bAKIA[A-Z0-9]{16}\b/g,
	/\bsk-[A-Za-z0-9_-]{20,}\b/g,
];

export interface ProcessEnvironmentPolicyOptions {
	baseEnvironment?: NodeJS.ProcessEnv;
	overrides?: Record<string, string | undefined>;
	inheritEnvironment?: boolean;
	allowedSensitiveEnvironmentVariables?: readonly string[];
}

export interface PreparedProcessEnvironment {
	environment: Record<string, string>;
	omittedSensitiveNames: string[];
	secretValues: string[];
}

function normalizeEnvironmentName(name: string): string {
	return name.trim().toUpperCase();
}

function hasEmbeddedUrlCredentials(value: string): boolean {
	CREDENTIAL_URL_PATTERN.lastIndex = 0;
	return CREDENTIAL_URL_PATTERN.test(value);
}

export function isSensitiveEnvironmentVariable(
	name: string,
	value = "",
): boolean {
	const normalized = normalizeEnvironmentName(name);
	return (
		SENSITIVE_ENVIRONMENT_NAMES.has(normalized) ||
		SENSITIVE_ENVIRONMENT_SEGMENT.test(normalized) ||
		hasEmbeddedUrlCredentials(value)
	);
}

/**
 * Creates the environment passed to an agent-started process.
 *
 * Non-sensitive variables remain compatible with ordinary developer tooling.
 * Variables whose names or URL values indicate credentials are withheld unless
 * the host explicitly grants that exact name. Overrides are filtered by the
 * same rule, so a tool call cannot bypass the host policy by supplying `env`.
 */
export function prepareProcessEnvironment(
	options: ProcessEnvironmentPolicyOptions = {},
): PreparedProcessEnvironment {
	const allowed = new Set(
		(options.allowedSensitiveEnvironmentVariables ?? []).map(
			normalizeEnvironmentName,
		),
	);
	const combined: Record<string, string | undefined> = {
		...(options.inheritEnvironment === false
			? {}
			: (options.baseEnvironment ?? process.env)),
		...(options.overrides ?? {}),
	};
	const environment: Record<string, string> = {};
	const omittedSensitiveNames: string[] = [];
	const secretValues = new Set<string>();

	for (const [name, value] of Object.entries(combined)) {
		if (typeof value !== "string") continue;
		const sensitive = isSensitiveEnvironmentVariable(name, value);
		if (sensitive && value.length >= MIN_EXACT_SECRET_LENGTH) {
			secretValues.add(value);
		}
		if (sensitive && !allowed.has(normalizeEnvironmentName(name))) {
			omittedSensitiveNames.push(name);
			continue;
		}
		environment[name] = value;
	}

	return {
		environment,
		omittedSensitiveNames: omittedSensitiveNames.sort((left, right) =>
			left.localeCompare(right),
		),
		secretValues: [...secretValues].sort(
			(left, right) => right.length - left.length,
		),
	};
}

export function redactSensitiveText(
	value: string,
	secretValues: readonly string[] = [],
): string {
	let redacted = value;
	for (const secret of secretValues) {
		if (secret.length >= MIN_EXACT_SECRET_LENGTH) {
			redacted = redacted.replaceAll(secret, REDACTED);
		}
	}
	redacted = redacted
		.replace(PRIVATE_KEY_PATTERN, REDACTED)
		.replace(CREDENTIAL_URL_PATTERN, `$1${REDACTED}@`)
		.replace(AUTHORIZATION_PATTERN, `$1${REDACTED}`)
		.replace(BEARER_PATTERN, `$1${REDACTED}`)
		.replace(SECRET_ASSIGNMENT_PATTERN, `$1$2${REDACTED}$2`);
	for (const pattern of WELL_KNOWN_TOKEN_PATTERNS) {
		redacted = redacted.replace(pattern, REDACTED);
	}
	return redacted;
}

function exactSecretCarryLength(
	value: string,
	secretValues: readonly string[],
): number {
	let carryLength = 0;
	for (const secret of secretValues) {
		const maxPrefix = Math.min(secret.length, value.length);
		for (
			let prefixLength = maxPrefix;
			prefixLength > carryLength;
			prefixLength -= 1
		) {
			if (value.endsWith(secret.slice(0, prefixLength))) {
				carryLength = prefixLength;
				break;
			}
		}
	}
	return carryLength;
}

function syntaxCarryLength(value: string): number {
	const tail = value.slice(-MAX_SYNTAX_CARRY_CHARS);
	const lineStart =
		Math.max(tail.lastIndexOf("\n"), tail.lastIndexOf("\r")) + 1;
	const line = tail.slice(lineStart);
	if (
		/(?:bearer\s+\S*|(?:authorization|api[_ -]?key|access[_ -]?token|refresh[_ -]?token|password|private[_ -]?key|secret|token)\s*[:=]\s*\S*|-----BEGIN [^-]*PRIVATE KEY-----[\s\S]*)$/i.test(
			line,
		)
	) {
		return line.length;
	}
	return 0;
}

export interface StreamingSecretRedactor {
	push(value: string): string;
	finish(): string;
}

/**
 * Redacts known values even when a process splits them across stdout chunks.
 * It retains only suffixes that could complete a known secret or sensitive
 * assignment, avoiding the fixed-size delay of a generic holdback buffer.
 */
export function createStreamingSecretRedactor(
	secretValues: readonly string[] = [],
): StreamingSecretRedactor {
	const normalizedSecrets = [...new Set(secretValues)]
		.filter((secret) => secret.length >= MIN_EXACT_SECRET_LENGTH)
		.sort((left, right) => right.length - left.length);
	let carry = "";

	return {
		push(value: string): string {
			if (!value) return "";
			const combined = carry + value;
			const carryLength = Math.max(
				exactSecretCarryLength(combined, normalizedSecrets),
				syntaxCarryLength(combined),
			);
			const emit = carryLength > 0 ? combined.slice(0, -carryLength) : combined;
			carry = carryLength > 0 ? combined.slice(-carryLength) : "";
			return redactSensitiveText(emit, normalizedSecrets);
		},
		finish(): string {
			const finalValue = redactSensitiveText(carry, normalizedSecrets);
			carry = "";
			normalizedSecrets.length = 0;
			return finalValue;
		},
	};
}
