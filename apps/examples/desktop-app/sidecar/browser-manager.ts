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
	private readonly pending = new Map<string, PendingRequest>();
	private readonly now: () => number;
	readonly executor: BrowserExecutor;

	constructor(private readonly options: BrowserManagerOptions) {
		this.now = options.now ?? Date.now;
		this.executor = (input, context) => this.execute(input, context);
	}

	list(): Array<Record<string, unknown>> {
		this.expire();
		return [...this.sessions.values()].map((session) => ({
			browserSessionId: session.browserSessionId,
			createdAt: new Date(session.createdAtMs).toISOString(),
			lastUsedAt: new Date(session.lastUsedAtMs).toISOString(),
			url: session.url,
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
	}

	private expire(): void {
		const cutoff = this.now() - MAX_SESSION_AGE_MS;
		for (const [id, session] of this.sessions) {
			if (session.lastUsedAtMs < cutoff) {
				this.sessions.delete(id);
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
		if (input.action === "list") return output({ sessions: this.list() });
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
			return output({
				browserSessionId: session.browserSessionId,
				stopped: true,
			});
		}
		const result = await this.request(session.browserSessionId, input.action, {
			...input,
			browser_session_id: undefined,
			action: undefined,
		});
		if (input.action === "navigate") session.url = input.url;
		return output(result);
	}
}
