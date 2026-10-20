import { realpathSync } from "node:fs";
import { relative, isAbsolute } from "node:path";
import {
	readGlobalSettings,
	resolvePermissionProfile,
	type PermissionProfile,
} from "@cline/core";
export function allowsAutomaticTaskValidation(
	config: Record<string, unknown>,
): boolean {
	if (
		config.mode === "plan" ||
		(config.mode !== "yolo" && config.autoApproveTools !== true)
	)
		return false;
	const raw =
		config.permissionProfile ??
		config.permission_profile ??
		readGlobalSettings().permissionProfile ??
		"full-access";
	try {
		if (
			typeof raw !== "string" &&
			(!raw ||
				typeof raw !== "object" ||
				(raw as { kind?: unknown }).kind !== "custom")
		)
			return false;
		const p = resolvePermissionProfile(raw as PermissionProfile);
		// Auto-approval never widens the capability profile. Arbitrary validation shells
		// may write or access the network, so restricted profiles use reviewed tool calls.
		return (
			!!p &&
			p.allowCommands &&
			p.allowFileWrites &&
			p.allowNetwork &&
			!p.deniedToolNames.has("run_commands") &&
			!p.deniedToolNames.has("task_validation")
		);
	} catch {
		return false;
	}
}

/** A plan string cannot authorize a new filesystem boundary or a symlink escape. */
export function automaticValidationCwd(
	config: Record<string, unknown>,
	worktree?: string,
): string | undefined {
	try {
		const root =
			typeof config.workspaceRoot === "string"
				? config.workspaceRoot
				: config.cwd;
		if (typeof root !== "string" || !root.trim()) return undefined;
		const canonicalRoot = realpathSync(root);
		const requested =
			worktree?.trim() ||
			(typeof config.cwd === "string" ? config.cwd.trim() : "") ||
			canonicalRoot;
		const canonical = realpathSync(requested),
			delta = relative(canonicalRoot, canonical);
		return delta === "" ||
			(!isAbsolute(delta) &&
				delta !== ".." &&
				!delta.startsWith("../") &&
				!delta.startsWith("..\\"))
			? canonical
			: undefined;
	} catch {
		return undefined;
	}
}
