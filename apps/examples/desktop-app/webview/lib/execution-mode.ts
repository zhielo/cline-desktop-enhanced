import type { ChatSessionConfig } from "@/lib/chat-schema";

export type ExecutionMode = ChatSessionConfig["mode"];

export function executionPolicyForMode(
	mode: ExecutionMode,
): Pick<ChatSessionConfig, "mode" | "autoApproveTools"> {
	return {
		mode,
		autoApproveTools: mode === "yolo",
	};
}

export function applyExecutionMode(
	config: ChatSessionConfig,
	mode: ExecutionMode,
): ChatSessionConfig {
	const policy = executionPolicyForMode(mode);
	if (
		config.mode === policy.mode &&
		config.autoApproveTools === policy.autoApproveTools
	) {
		return config;
	}
	return { ...config, ...policy };
}
