import type {
	AgentToolContext,
	BasicLogger,
	ClineCore,
	ITelemetryService,
	ManagedHubBuildMismatchEvent,
	NodeHubClient,
	RemoteEnvironmentConnection,
	RemoteEnvironmentService,
	ToolApprovalResult,
} from "@cline/core";
import type { MessageWithMetadata } from "@cline/llms";
import type { UserContext } from "@cline/shared";

export const LOCAL_ENVIRONMENT_ID = "local";

export type JsonRecord = Record<string, unknown>;

export type ChatTurnAttachments = {
	userImages?: string[];
	userFiles?: Array<
		| { name: string; uploadId: string }
		| { name: string; content: string }
	>;
};

export type ChatSessionCommandRequest = {
	action:
		| "start"
		| "attach"
		| "send"
		| "stop"
		| "abort"
		| "fork"
		| "reset"
		| "restore_checkpoint"
		| "pending_prompts"
		| "steer_prompt"
		| "update_pending_prompt"
		| "remove_pending_prompt";
	sessionId?: string;
	prompt?: string;
	promptId?: string;
	checkpointRunCount?: number;
	forkBeforeRunCount?: number;
	delivery?: "queue" | "steer";
	config?: JsonRecord;
	attachments?: ChatTurnAttachments;
};

export type PromptInQueue = {
	id: string;
	prompt: string;
	steer: boolean;
	attachmentCount?: number;
	userImages?: string[];
};

export type LiveSession = {
	environmentId?: string;
	config: JsonRecord;
	messages: MessageWithMetadata[];
	promptsInQueue: PromptInQueue[];
	busy: boolean;
	startedAt: number;
	endedAt?: number;
	status: string;
	transitioningProvider?: boolean;
	prompt?: string;
	title?: string;
	attachedViaHub?: boolean;
	lastHubStatusSequence?: number;
	mistakeRecovery?: {
		latestIteration: number;
		continuedThroughIteration?: number;
	};
	queuedAttachmentFiles?: Map<string, string[]>;
	lastQueuedPromptStartId?: string;
	consumedAttachmentFiles?: Map<string, string[]>;
};

export type SessionRuntimeBinding = {
	environmentId: string;
	kind: "local" | "ssh";
	workspaceRoot: string;
	sessionManager: ClineCore;
	hubClient: NodeHubClient;
	unsubscribeSessionEvents: () => void;
	remote?: RemoteEnvironmentConnection;
};

export type ToolApprovalRequestItem = {
	requestId: string;
	sessionId: string;
	createdAt: string;
	toolCallId: string;
	toolName: string;
	input?: unknown;
	iteration?: number;
	agentId?: string;
	conversationId?: string;
};

export type PendingToolApproval = {
	item: ToolApprovalRequestItem;
	owner?: SidecarWebSocketClient;
	resolve: (result: ToolApprovalResult) => void | Promise<void>;
};

export type AskQuestionRequestItem = {
	requestId: string;
	sessionId: string;
	createdAt: string;
	question: string;
	options: string[];
	context?: Pick<
		AgentToolContext,
		"agentId" | "conversationId" | "iteration" | "metadata"
	>;
};

export type PendingAskQuestion = {
	item: AskQuestionRequestItem;
	resolve: (answer: string) => void;
	reject: (error: Error) => void;
	timeoutId?: ReturnType<typeof setTimeout>;
};

export type SidecarWebSocketClient = {
	data?: {
		/** Per-launch secret was supplied and matched. */
		authenticated?: boolean;
		/** This connection is the trusted browser UI allowed to resolve approvals. */
		canApproveTools?: boolean;
	};
	send: (message: string) => void;
	close?: () => void;
};

export type SidecarContext = {
	liveSessions: Map<string, LiveSession>;
	restoringWorkspacePaths: Set<string>;
	streamIndices: Map<string, number>;
	bootId: string;
	wsClients: Set<SidecarWebSocketClient>;
	pendingApprovals: Map<string, PendingToolApproval>;
	pendingQuestions: Map<string, PendingAskQuestion>;
	runtimeBindings: Map<string, SessionRuntimeBinding>;
	sessionEnvironmentIds: Map<string, string>;
	activeEnvironmentId: string;
	remoteEnvironments: RemoteEnvironmentService | null;
	localWorkspaceRoot: string;
	logger?: BasicLogger;
	telemetry?: ITelemetryService;
	telemetryUser?: UserContext;
	cloudSessionManager: {
		dispose(): Promise<void>;
		isCloudSession(sessionId: string): boolean;
	} | null;
	hubBuildMismatch: ManagedHubBuildMismatchEvent | null;
};

export type BunRuntimeApi = {
	serve: (options: unknown) => { port: number; stop?: () => void };
};

export const BunRuntime = (globalThis as { Bun?: BunRuntimeApi }).Bun;
export const SIDECAR_PORT = Number(process.env.CLINE_SIDECAR_PORT) || 3126;
export const SIDECAR_HOST =
	process.env.CLINE_SIDECAR_HOST?.trim() || "127.0.0.1";
export const SIDECAR_MODE = "sidecar";
