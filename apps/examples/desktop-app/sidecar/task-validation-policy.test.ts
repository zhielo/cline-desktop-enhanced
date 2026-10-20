import { afterEach, describe, it, expect } from "vitest";
import { mkdtempSync, rmSync, mkdirSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
	allowsAutomaticTaskValidation,
	automaticValidationCwd,
} from "./task-validation-policy";
const roots: string[] = [];
function root() {
	const p = mkdtempSync(join(tmpdir(), "validation-policy-"));
	roots.push(p);
	return p;
}
afterEach(() => {
	for (const p of roots.splice(0)) rmSync(p, { recursive: true, force: true });
});
describe("automatic validation permission boundary", () => {
	for (const profile of [
		"read-only",
		"workspace",
		"notion-functions",
		"project-notion-bridge",
		"unknown",
	])
		it(`does not widen ${profile} using yolo/autoApprove`, () => {
			expect(
				allowsAutomaticTaskValidation({
					permissionProfile: profile,
					mode: "yolo",
					autoApproveTools: true,
				}),
			).toBe(false);
		});
	it("requires explicit automatic command approval and denies Plan mode", () => {
		expect(
			allowsAutomaticTaskValidation({
				permissionProfile: "full-access",
				mode: "act",
			}),
		).toBe(false);
		expect(
			allowsAutomaticTaskValidation({
				permissionProfile: "full-access",
				mode: "plan",
				autoApproveTools: true,
			}),
		).toBe(false);
		expect(
			allowsAutomaticTaskValidation({
				permissionProfile: "full-access",
				mode: "yolo",
			}),
		).toBe(true);
		expect(
			allowsAutomaticTaskValidation({
				permissionProfile: "workspace-network",
				mode: "act",
				autoApproveTools: true,
			}),
		).toBe(true);
	});
	it("respects custom denies, capability limits and the snake-case profile", () => {
		const config = {
			mode: "yolo",
			permissionProfile: {
				kind: "custom",
				name: "test",
				allowCommands: true,
				allowFileWrites: true,
				allowNetwork: true,
				allowExternalTools: false,
				allowUnknownTools: false,
				allowProcessSessions: false,
			},
		};
		expect(allowsAutomaticTaskValidation(config)).toBe(true);
		expect(
			allowsAutomaticTaskValidation({
				...config,
				permissionProfile: {
					...config.permissionProfile,
					deniedToolNames: ["run_commands"],
				},
			}),
		).toBe(false);
		expect(
			allowsAutomaticTaskValidation({
				...config,
				permissionProfile: {
					...config.permissionProfile,
					allowCommands: false,
				},
			}),
		).toBe(false);
		expect(
			allowsAutomaticTaskValidation({
				mode: "yolo",
				permission_profile: "read-only",
			}),
		).toBe(false);
	});
	it("canonicalizes owned directories and rejects external or symlink worktrees", () => {
		const owned = root(),
			outside = root();
		mkdirSync(join(owned, "sub"));
		symlinkSync(
			outside,
			join(owned, "escape"),
			process.platform === "win32" ? "junction" : "dir",
		);
		expect(
			automaticValidationCwd({ workspaceRoot: owned }, join(owned, "sub")),
		).toBeDefined();
		expect(
			automaticValidationCwd({ workspaceRoot: owned }, outside),
		).toBeUndefined();
		expect(
			automaticValidationCwd({ workspaceRoot: owned }, join(owned, "escape")),
		).toBeUndefined();
	});
});
