import { mkdirSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createCoreSettingsService } from "@cline/core";
import { setHomeDir } from "@cline/shared/storage";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { handleCommand } from "./commands";
import {
	inspectInvestigationSkillPack,
	INVESTIGATION_PLUGIN_NAME,
	INVESTIGATION_SKILL_NAMES,
} from "./investigation-skills";
import type { SidecarContext } from "./types";

let root: string;
const envKeys = [
	"HOME",
	"CLINE_DIR",
	"CLINE_DATA_DIR",
	"CLINE_GLOBAL_SETTINGS_PATH",
	"CLINE_MCP_SETTINGS_PATH",
] as const;
let previous: Record<string, string | undefined>;
beforeEach(() => {
	previous = Object.fromEntries(envKeys.map((k) => [k, process.env[k]]));
	root = mkdtempSync(join(tmpdir(), "cline-command-skills-"));
	process.env.HOME = root;
	setHomeDir(root);
	process.env.CLINE_DIR = join(root, "profile");
	process.env.CLINE_DATA_DIR = join(root, "data");
	process.env.CLINE_GLOBAL_SETTINGS_PATH = join(root, "settings.json");
	process.env.CLINE_MCP_SETTINGS_PATH = join(root, "mcp.json");
	mkdirSync(join(root, "workspace"));
});
afterEach(() => {
	for (const k of envKeys) {
		if (previous[k] === undefined) delete process.env[k];
		else process.env[k] = previous[k];
	}
	setHomeDir(previous.HOME ?? "~");
	rmSync(root, { recursive: true, force: true });
});
function context(environment = "local") {
	const settings = createCoreSettingsService();
	const command = vi.fn(
		async (name: string, input: Record<string, unknown>) => {
			if (name === "settings.list")
				return { ok: true, payload: { snapshot: await settings.list(input) } };
			if (name === "settings.toggle")
				return {
					ok: true,
					payload: await settings.toggle(
						input as unknown as Parameters<typeof settings.toggle>[0],
					),
				};
			throw new Error(`Unexpected owned fixture command ${name}`);
		},
	);
	const ctx = {
		localWorkspaceRoot: join(root, "workspace"),
		activeEnvironmentId: environment,
		runtimeBindings: new Map([
			["local", { kind: "local", hubClient: { command } }],
		]),
	} as unknown as SidecarContext;
	return { ctx, command };
}
type Catalog = {
	skills: Array<{
		id: string;
		agentPlugin?: boolean;
		pluginName?: string;
		instructions: string;
	}>;
	plugins: Array<{ name: string; path: string; enabled: boolean }>;
	runtimeCommands: Array<{ id: string }>;
	bundledInvestigationSkills: { status: string; reason?: string };
};
const ownSkills = (c: Catalog) =>
	c.skills.filter((s) => s.id.startsWith(`${INVESTIGATION_PLUGIN_NAME}:`));
const ownCommands = (c: Catalog) =>
	c.runtimeCommands.filter((s) =>
		s.id.startsWith(`${INVESTIGATION_PLUGIN_NAME}:`),
	);
describe("shipped investigation command integration", () => {
	it("lists all namespaced bodies with immutable Agent Plugin controls and no Hub startup", async () => {
		const { ctx, command } = context();
		const catalog = (await handleCommand(
			ctx,
			"list_user_instruction_configs",
		)) as Catalog;
		expect(catalog.bundledInvestigationSkills.status).toBe("available");
		expect(
			ownSkills(catalog)
				.map((s) => s.id)
				.sort(),
		).toEqual(
			INVESTIGATION_SKILL_NAMES.map(
				(n) => `${INVESTIGATION_PLUGIN_NAME}:${n}`,
			).sort(),
		);
		expect(ownCommands(catalog)).toHaveLength(10);
		for (const skill of ownSkills(catalog)) {
			expect(skill.agentPlugin).toBe(true);
			expect(skill.pluginName).toBe(INVESTIGATION_PLUGIN_NAME);
			expect(skill.instructions).toContain("receipt");
		}
		expect(command).toHaveBeenCalledWith(
			"settings.list",
			expect.objectContaining({
				agentPluginPaths: inspectInvestigationSkillPack(true).paths,
			}),
		);
	});
	it("persists plugin disablement across a fresh context without rewriting shipped instructions", async () => {
		const { ctx } = context();
		const pack = inspectInvestigationSkillPack(true);
		if (pack.status !== "available")
			throw new Error("Owned source pack missing");
		const path = pack.root;
		const member = join(path, "skills", "analyze-electron", "SKILL.md");
		const before = readFileSync(member);
		const off = (await handleCommand(ctx, "set_plugin_disabled", {
			path,
			disabled: true,
		})) as Catalog;
		expect(ownSkills(off)).toEqual([]);
		expect(ownCommands(off)).toEqual([]);
		expect(
			off.plugins.find((p) => p.name === INVESTIGATION_PLUGIN_NAME)?.enabled,
		).toBe(false);
		const restarted = context();
		const retained = (await handleCommand(
			restarted.ctx,
			"list_user_instruction_configs",
		)) as Catalog;
		expect(ownSkills(retained)).toEqual([]);
		expect(ownCommands(retained)).toEqual([]);
		const on = (await handleCommand(restarted.ctx, "set_plugin_disabled", {
			path,
			disabled: false,
		})) as Catalog;
		expect(ownSkills(on)).toHaveLength(10);
		expect(ownCommands(on)).toHaveLength(10);
		expect(readFileSync(member)).toEqual(before);
	});
	it("does not project host skill paths or bodies into a nonlocal environment", async () => {
		const { ctx, command } = context("ssh:owned");
		const catalog = (await handleCommand(
			ctx,
			"list_user_instruction_configs",
		)) as Catalog;
		expect(catalog.bundledInvestigationSkills).toMatchObject({
			status: "unavailable",
			reason: "not-local",
		});
		expect(ownSkills(catalog)).toEqual([]);
		expect(ownCommands(catalog)).toEqual([]);
		expect(command).toHaveBeenCalledWith(
			"settings.list",
			expect.objectContaining({ agentPluginPaths: [] }),
		);
	});
});
