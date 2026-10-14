/**
 * Constants for Default Tools
 *
 * Tool name constants and utility arrays.
 */

import type { DefaultToolName } from "./types";

/**
 * Constants for default tool names
 */
export const DefaultToolNames = {
	OPEN_BINARY: "open_binary",
	ANALYZE_FUNCTION: "analyze_function",
	TRACE_APPLICATION_FEATURE: "trace_application_feature",
	CAPTURE_BROWSER_SCENARIO: "capture_browser_scenario",
	GET_EVIDENCE_BUNDLE: "get_evidence_bundle",
	READ_FILES: "read_files",
	SEARCH_CODEBASE: "search_codebase",
	REVERSE_ENGINEER: "reverse_engineer",
	LIVE_DEBUGGER: "live_debugger",
	ANDROID_DEVICE: "android_device",
	RUN_COMMANDS: "run_commands",
	PROCESS_SESSION: "process_session",
	COMPUTER_USE: "computer_use",
	BROWSER: "browser",
	REPOSITORY: "repository",
	FETCH_WEB_CONTENT: "fetch_web_content",
	APPLY_PATCH: "apply_patch",
	EDITOR: "editor",
	SKILLS: "skills",
	ASK: "ask_question",
	SUBMIT_AND_EXIT: "submit_and_exit",
} as const;

/**
 * Array of all default tool names
 */
export const ALL_DEFAULT_TOOL_NAMES: DefaultToolName[] = [
	DefaultToolNames.OPEN_BINARY,
	DefaultToolNames.ANALYZE_FUNCTION,
	DefaultToolNames.TRACE_APPLICATION_FEATURE,
	DefaultToolNames.CAPTURE_BROWSER_SCENARIO,
	DefaultToolNames.GET_EVIDENCE_BUNDLE,
	DefaultToolNames.READ_FILES,
	DefaultToolNames.SEARCH_CODEBASE,
	DefaultToolNames.REVERSE_ENGINEER,
	DefaultToolNames.LIVE_DEBUGGER,
	DefaultToolNames.ANDROID_DEVICE,
	DefaultToolNames.RUN_COMMANDS,
	DefaultToolNames.PROCESS_SESSION,
	DefaultToolNames.COMPUTER_USE,
	DefaultToolNames.BROWSER,
	DefaultToolNames.REPOSITORY,
	DefaultToolNames.FETCH_WEB_CONTENT,
	DefaultToolNames.APPLY_PATCH,
	DefaultToolNames.EDITOR,
	DefaultToolNames.SKILLS,
	DefaultToolNames.ASK,
	DefaultToolNames.SUBMIT_AND_EXIT,
];
