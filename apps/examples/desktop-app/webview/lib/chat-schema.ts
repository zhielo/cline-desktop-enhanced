import { GeneratedMediaSchema } from "@cline/shared/browser";
import { z } from "zod";

export const ChatSessionConfigSchema = z.object({
	sessionId: z.string().min(1).optional(),
	executionTarget: z.enum(["local", "cloud"]).default("local"),
	repoUrl: z.string().optional(),
	branch: z.string().optional(),
	workspaceRoot: z.string(),
	cwd: z.string().optional(),
	environmentId: z.string().trim().min(1),
	provider: z.string().min(1),
	model: z.string().min(1),
	mode: z.enum(["act", "plan", "yolo"]).default("yolo"),
	apiKey: z.string(),
	systemPrompt: z.string().optional(),
	rules: z.string().optional(),
	maxIterations: z.number().int().positive().optional(),
	apiTimeoutMs: z.number().int().positive().optional(),
	thinking: z.boolean().optional(),
	reasoningEffort: z.enum(["low", "medium", "high", "xhigh"]).optional(),
	enableTools: z.boolean(),
	autoApproveTools: z.boolean().optional(),
	missionStepInterval: z.number().int().positive().optional(),
	missionTimeIntervalMs: z.number().int().positive().optional(),
});

export const ChatSessionStatusSchema = z.enum([
	"idle",
	"starting",
	"running",
	"stopping",
	"completed",
	"cancelled",
	"failed",
	"error",
]);

export const ChatMessageRoleSchema = z.enum([
	"user",
	"assistant",
	"tool",
	"system",
	"status",
	"error",
]);

export const ChatMessageImageSchema = z.object({
	id: z.string().min(1),
	mediaType: z.enum(["image/png", "image/jpeg", "image/gif", "image/webp"]),
	data: z.string().min(1),
});

export const ChatMessageMediaSchema = GeneratedMediaSchema;

export const TaskStepStatusSchema = z.enum([
	"pending",
	"in_progress",
	"blocked",
	"waiting_for_user",
	"completed",
	"failed",
	"skipped",
	"cancelled",
]);

export const TaskStepKindSchema = z.enum(["work", "repair", "verification"]);

export const TaskExecutionStatusSchema = z.enum([
	"planned",
	"running",
	"verifying",
	"repairing",
	"completed",
	"waiting_for_user",
	"blocked",
	"failed",
	"cancelled",
	"skipped",
]);

export const TaskPlanStepSchema = z.object({
	id: z.string().min(1),
	label: z.string().min(1),
	status: TaskStepStatusSchema,
	kind: TaskStepKindSchema.default("work"),
	parentStepId: z.string().min(1).optional(),
	acceptanceCriteria: z.array(z.string().min(1)).optional(),
	validationCommands: z.array(z.string().min(1)).optional(),
	ownerAgentId: z.string().min(1).optional(),
	worktree: z.string().min(1).optional(),
	artifacts: z.array(z.string().min(1)).optional(),
	startedAtMs: z.number().int().nonnegative().optional(),
	completedAtMs: z.number().int().nonnegative().optional(),
	repairAttempt: z.number().int().nonnegative().optional(),
	maxRepairAttempts: z.number().int().nonnegative().optional(),
});

export const TaskProtocolEventSchema = z.discriminatedUnion("type", [
	z.object({
		type: z.literal("plan.updated"),
		planId: z.string().min(1),
		explanation: z.string().optional(),
		state: TaskExecutionStatusSchema.optional(),
		steps: z.array(TaskPlanStepSchema),
		activeStepId: z.string().min(1).optional(),
		repair: z
			.object({
				state: z
					.enum(["repair_required", "repairing", "verifying", "blocked"])
					.optional(),
				attempt: z.number().int().nonnegative().optional(),
				maxAttempts: z.number().int().positive().optional(),
			})
			.optional(),
		updatedAtMs: z.number().int().nonnegative().optional(),
		transitions: z
			.array(
				z.object({
					from: TaskExecutionStatusSchema.optional(),
					to: TaskExecutionStatusSchema,
					atMs: z.number().int().nonnegative(),
					reason: z.string().min(1),
				}),
			)
			.optional(),
	}),
	z.object({
		type: z.literal("tool.started"),
		toolCallId: z.string().min(1),
		toolName: z.string().min(1),
		stepId: z.string().min(1).optional(),
	}),
	z.object({
		type: z.literal("tool.completed"),
		toolCallId: z.string().min(1),
		toolName: z.string().min(1),
		stepId: z.string().min(1).optional(),
		durationMs: z.number().nonnegative().optional(),
	}),
	z.object({
		type: z.literal("tool.failed"),
		toolCallId: z.string().min(1),
		toolName: z.string().min(1),
		stepId: z.string().min(1).optional(),
		durationMs: z.number().nonnegative().optional(),
		error: z.string().optional(),
	}),
]);

export const ChatMessageSchema = z.object({
	id: z.string().min(1),
	sessionId: z.string().nullable(),
	role: ChatMessageRoleSchema,
	content: z.string(),
	images: z.array(ChatMessageImageSchema).optional(),
	media: z.array(ChatMessageMediaSchema).optional(),
	reasoning: z.string().optional(),
	reasoningRedacted: z.boolean().optional(),
	createdAt: z.number().int().nonnegative(),
	meta: z
		.object({
			stream: z.enum(["stdout", "stderr"]).optional(),
			toolName: z.string().optional(),
			toolCallId: z.string().optional(),
			taskStepId: z.string().optional(),
			taskEvent: TaskProtocolEventSchema.optional(),
			toolOutput: z.string().optional(),
			toolOutputTruncated: z.boolean().optional(),
			toolDetachable: z.boolean().optional(),
			iteration: z.number().int().nonnegative().optional(),
			agentId: z.string().optional(),
			conversationId: z.string().optional(),
			hookEventName: z.string().optional(),
			messageKind: z.string().optional(),
			displayRole: z.string().optional(),
			reason: z.string().optional(),
			inputTokens: z.number().int().nonnegative().optional(),
			outputTokens: z.number().int().nonnegative().optional(),
			cacheReadTokens: z.number().int().nonnegative().optional(),
			totalCost: z.number().nonnegative().optional(),
			providerId: z.string().optional(),
			modelId: z.string().optional(),
			userRunSpan: z.number().int().nonnegative().optional(),
			runCount: z.number().int().positive().optional(),
			checkpoint: z
				.object({
					ref: z.string(),
					createdAt: z.number().int().nonnegative(),
					runCount: z.number().int().positive(),
					kind: z.enum(["stash", "commit"]).optional(),
				})
				.optional(),
		})
		.optional(),
});

export const ChatSummarySchema = z.object({
	toolCalls: z.number().int().nonnegative(),
	tokensIn: z.number().int().nonnegative(),
	tokensOut: z.number().int().nonnegative(),
});

export const ChatViewStateSchema = z.object({
	sessionId: z.string().nullable(),
	status: ChatSessionStatusSchema,
	config: ChatSessionConfigSchema,
	messages: z.array(ChatMessageSchema),
	rawTranscript: z.string(),
	error: z.string().nullable(),
	summary: ChatSummarySchema,
});

export type ChatSessionConfig = z.infer<typeof ChatSessionConfigSchema>;
export type ChatSessionStatus = z.infer<typeof ChatSessionStatusSchema>;
export type TaskPlanStep = z.infer<typeof TaskPlanStepSchema>;
export type TaskProtocolEvent = z.infer<typeof TaskProtocolEventSchema>;
export type TaskPlanUpdatedEvent = Extract<
	TaskProtocolEvent,
	{ type: "plan.updated" }
>;
export type ChatMessageImage = z.infer<typeof ChatMessageImageSchema>;
export type ChatMessageMedia = z.infer<typeof ChatMessageMediaSchema>;
export type ChatMessage = z.infer<typeof ChatMessageSchema>;
export type ChatSummary = z.infer<typeof ChatSummarySchema>;
export type ChatViewState = z.infer<typeof ChatViewStateSchema>;
