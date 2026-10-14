import { randomUUID } from "node:crypto";
import type {
	AgentToolContext,
	BrowserExecutor,
	BrowserInput,
} from "@cline/core";

const MAX_SESSIONS = 8;
const MAX_SESSION_AGE_MS = 30 * 60_000;
const REQUEST_TIMEOUT_MS = 35_000;

export type BrowserBridgeRequest = {
	requestId: string;
	browserSessionId: string;
	operation: string;
	payload: Record<string, unknown>;
};

type BrowserSession = {
	browserSessionId: string;
	ownerSessionId: string;
	createdAtMs: number;
	lastUsedAtMs: number;
	url?: string;
};

type PendingRequest = {
	resolve: (value: unknown) => void;
	reject: (error: Error) => void;
	timer: ReturnType<typeof setTimeout>;
};

type BrowserManagerOptions = {
	onRequest: (request: BrowserBridgeRequest) => void;
	now?: () => number;
};

function ownerId(context: AgentToolContext): string {
	if (!context.sessionId)
		throw new Error("browser requires a host-provided sessionId");
	return context.sessionId;
}

function output(value: unknown): string {
	return JSON.stringify(value, null, 2);
}

export class DesktopBrowserManager {
	private readonly sessions = new Map<string, BrowserSession>();
	private readonly captures = new Map<
		string,
		{
			owner: string;
			purpose: string;
			started: number;
			actions: Array<Record<string, unknown>>;
			droppedActions: number;
		}
	>();
	private readonly pending = new Map<string, PendingRequest>();
	private readonly now: () => number;
	readonly executor: BrowserExecutor;

	constructor(private readonly options: BrowserManagerOptions) {
		this.now = options.now ?? Date.now;
		this.executor = (input, context) => this.execute(input, context);
	}

	list(owner?: string): Array<Record<string, unknown>> {
		this.expire();
		return [...this.sessions.values()]
			.filter((session) => !owner || session.ownerSessionId === owner)
			.map((session) => ({
				browserSessionId: session.browserSessionId,
				createdAt: new Date(session.createdAtMs).toISOString(),
				lastUsedAt: new Date(session.lastUsedAtMs).toISOString(),
				url: session.url,
				recording: this.captures.has(session.browserSessionId),
			}));
	}

	resolveRequest(requestId: string, result: unknown, error?: string): boolean {
		const pending = this.pending.get(requestId);
		if (!pending) return false;
		this.pending.delete(requestId);
		clearTimeout(pending.timer);
		if (error) pending.reject(new Error(error));
		else pending.resolve(result);
		return true;
	}

	async stopAll(): Promise<void> {
		await Promise.allSettled(
			[...this.sessions.keys()].map((id) =>
				this.request(id, "stop", {}).catch(() => undefined),
			),
		);
		this.sessions.clear();
		this.captures.clear();
	}

	async captureScenario(
		owner: string,
		input: Record<string, unknown>,
	): Promise<unknown> {
		const id = String(input.browserSessionId ?? "");
		this.requireSession(id, { sessionId: owner } as AgentToolContext);
		if (input.confirmRecord !== true)
			throw new Error("Explicit browser recording consent required");
		if (input.action === "start") {
			if (this.captures.has(id))
				throw new Error("Capture already active or cleanup unconfirmed");
			const capture = {
				owner,
				purpose: String(input.purpose ?? "").slice(0, 160),
				started: this.now(),
				actions: [] as Array<Record<string, unknown>>,
				droppedActions: 0,
			};
			this.captures.set(id, capture);
			try {
				return await this.request(id, "capture_start", {});
			} catch (error) {
				try {
					await this.request(id, "capture_stop", {});
					this.captures.delete(id);
				} catch {
					/* Preserve uncertainty; explicit stop is required. */
				}
				throw error;
			}
		}
		const capture = this.captures.get(id);
		if (!capture || capture.owner !== owner)
			throw new Error("No owning browser capture");
		const metadata = await this.request(id, "capture_stop", {});
		this.captures.delete(id);
		const m = metadata as {
			cleanupVerified?: boolean;
			expired?: boolean;
			dropped?: number;
		};
		return {
			purpose: capture.purpose,
			status:
				m?.cleanupVerified === true &&
				!m.expired &&
				!m.dropped &&
				!capture.droppedActions
					? "completed"
					: "partial",
			metadata,
			actions: capture.actions,
			droppedActions: capture.droppedActions,
			coverage: "approved-browser-actions-and-native-metadata",
			limitations: [
				"No screenshots, bodies, headers, cookies or console argument values are retained.",
				"Action acknowledgements and protocol events do not prove a feature call chain.",
			],
		};
	}
	private expire(): void {
		const cutoff = this.now() - MAX_SESSION_AGE_MS;
		for (const [id, session] of this.sessions) {
			if (session.lastUsedAtMs < cutoff) {
				this.sessions.delete(id);
				this.captures.delete(id);
				void this.request(id, "stop", {}).catch(() => undefined);
			}
		}
	}

	private request(
		browserSessionId: string,
		operation: string,
		payload: Record<string, unknown>,
	): Promise<unknown> {
		const requestId = randomUUID();
		return new Promise((resolve, reject) => {
			const timer = setTimeout(() => {
				this.pending.delete(requestId);
				reject(new Error(`Built-in browser ${operation} timed out`));
			}, REQUEST_TIMEOUT_MS);
			this.pending.set(requestId, { resolve, reject, timer });
			this.options.onRequest({
				requestId,
				browserSessionId,
				operation,
				payload,
			});
		});
	}

	private requireSession(
		id: string,
		context: AgentToolContext,
	): BrowserSession {
		this.expire();
		const session = this.sessions.get(id);
		if (!session || session.ownerSessionId !== ownerId(context)) {
			throw new Error("Unknown browser session or session ownership mismatch");
		}
		session.lastUsedAtMs = this.now();
		return session;
	}

	private async execute(
		input: BrowserInput,
		context: AgentToolContext,
	): Promise<string> {
		if (input.action === "list")
			return output({ sessions: this.list(ownerId(context)) });
		if (input.action === "start") {
			if (context.snapshot?.parentAgentId) {
				throw new Error("Child agents cannot start a built-in browser session");
			}
			this.expire();
			if (this.sessions.size >= MAX_SESSIONS) {
				throw new Error(
					`Built-in browser session limit reached (${MAX_SESSIONS})`,
				);
			}
			const browserSessionId = randomUUID();
			const initialUrl = input.url ?? "about:blank";
			await this.request(browserSessionId, "start", { url: initialUrl });
			const timestamp = this.now();
			this.sessions.set(browserSessionId, {
				browserSessionId,
				ownerSessionId: ownerId(context),
				createdAtMs: timestamp,
				lastUsedAtMs: timestamp,
				url: initialUrl,
			});
			return output({ browserSessionId, url: initialUrl, isolated: true });
		}

		const session = this.requireSession(input.browser_session_id, context);
		if (input.action === "stop") {
			await this.request(session.browserSessionId, "stop", {});
			this.sessions.delete(session.browserSessionId);
			this.captures.delete(session.browserSessionId);
			return output({
				browserSessionId: session.browserSessionId,
				stopped: true,
			});
		}
		const begun = this.now();
		let result: unknown;
		let status = "failed";
		try {
			result = await this.request(session.browserSessionId, input.action, {
				...input,
				browser_session_id: undefined,
				action: undefined,
			});
			status = "acknowledged";
		} finally {
			const capture = this.captures.get(session.browserSessionId);
			if (capture) {
				if (
					this.now() - capture.started <= 120000 &&
					capture.actions.length < 100
				)
					capture.actions.push({
						action: input.action,
						startedAtMs: begun - capture.started,
						finishedAtMs: this.now() - capture.started,
						status,
						inputOmitted: true,
					});
				else capture.droppedActions++;
			}
		}
		if (input.action === "navigate") session.url = input.url;
		return output(result);
	}
}
