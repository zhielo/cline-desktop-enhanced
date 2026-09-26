/**
 * Built-in Executor Implementations
 *
 * This module provides ready-to-use implementations of the tool executors
 * using Node.js built-in modules. These can be used directly or as references
 * for custom implementations.
 */

import type { ToolExecutors } from "../types";
import { createAndroidDeviceExecutor } from "./android-device";
import {
	type ApplyPatchExecutorOptions,
	createApplyPatchExecutor,
} from "./apply-patch";
import { createShellExecutor, type ShellExecutorOptions } from "./bash";
import { createEditorExecutor, type EditorExecutorOptions } from "./editor";
import {
	createFileReadExecutor,
	type FileReadExecutorOptions,
} from "./file-read";
import { createLiveDebuggerExecutor } from "./live-debugger";
import { createReverseEngineeringExecutor } from "./reverse-engineering";
import { createSearchExecutor, type SearchExecutorOptions } from "./search";
import {
	createWebFetchExecutor,
	type WebFetchExecutorOptions,
} from "./web-fetch";

export { createAndroidDeviceExecutor } from "./android-device";
// Re-export individual executors and their options types
export {
	type ApplyPatchExecutorOptions,
	computePatchChanges,
	createApplyPatchExecutor,
	type PatchFileChange,
} from "./apply-patch";
export { PATCH_MARKERS, PatchActionType } from "./apply-patch-parser";
export {
	CommandExitError,
	createShellExecutor,
	type ShellExecutorOptions,
} from "./bash";
export { createEditorExecutor, type EditorExecutorOptions } from "./editor";
export {
	createFileReadExecutor,
	type FileReadExecutorOptions,
} from "./file-read";
export { createLiveDebuggerExecutor } from "./live-debugger";
export {
	DEFAULT_COMPLETED_PROCESS_RETENTION_MS,
	DEFAULT_MAX_PROCESS_SESSIONS,
	DEFAULT_MAX_PROCESS_SESSIONS_PER_OWNER,
	DEFAULT_PROCESS_OUTPUT_BYTES,
	ProcessSessionManager,
	type ProcessSessionManagerOptions,
	type ProcessSessionOutputChunk,
	type ProcessSessionOutputStream,
	type ProcessSessionReadResult,
	type ProcessSessionSignal,
	type ProcessSessionSnapshot,
	type ProcessSessionStartOptions,
	type ProcessSessionState,
} from "./process-session-manager";
export { createReverseEngineeringExecutor } from "./reverse-engineering";
export {
	RunCommandExecutionController,
	type RunningCommandRegistration,
} from "./run-command-execution-controller";
export { createSearchExecutor, type SearchExecutorOptions } from "./search";
export {
	createWebFetchExecutor,
	type WebFetchExecutorOptions,
} from "./web-fetch";

/**
 * Options for creating default executors
 */
export interface DefaultExecutorsOptions {
	fileRead?: FileReadExecutorOptions;
	search?: SearchExecutorOptions;
	bash?: ShellExecutorOptions;
	webFetch?: WebFetchExecutorOptions;
	applyPatch?: ApplyPatchExecutorOptions;
	editor?: EditorExecutorOptions;
}

/**
 * Create the default shell executor for the current platform.
 *
 * This is factored out from {@link createDefaultExecutors} so host integrations
 * can reuse the SDK's cross-platform shell selection while supplying their own
 * tool wrapper.
 */
export function createDefaultShellExecutor(options: ShellExecutorOptions = {}) {
	return createShellExecutor(options);
}

/**
 * Create all default executors with optional configuration
 *
 * @example
 * ```typescript
 * import { createDefaultTools, createDefaultExecutors } from "@cline/core"
 *
 * const executors = createDefaultExecutors({
 *   bash: { timeoutMs: 60000 },
 *   search: { maxResults: 50 },
 * })
 *
 * const tools = createDefaultTools({
 *   executors,
 *   cwd: "/path/to/project",
 * })
 * ```
 */
export function createDefaultExecutors(
	options: DefaultExecutorsOptions = {},
): ToolExecutors {
	return {
		readFile: createFileReadExecutor(options.fileRead),
		search: createSearchExecutor(options.search),
		reverseEngineering: createReverseEngineeringExecutor(),
		liveDebugger: createLiveDebuggerExecutor(),
		androidDevice: createAndroidDeviceExecutor(),
		bash: createDefaultShellExecutor(options.bash),
		webFetch: createWebFetchExecutor(options.webFetch),
		applyPatch: createApplyPatchExecutor(options.applyPatch),
		editor: createEditorExecutor(options.editor),
	};
}
