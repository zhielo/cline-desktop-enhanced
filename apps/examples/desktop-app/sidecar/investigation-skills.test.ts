import { execFileSync } from "node:child_process";
import {
	cpSync,
	existsSync,
	linkSync,
	mkdirSync,
	mkdtempSync,
	readFileSync,
	readdirSync,
	rmSync,
	symlinkSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
const disabled = vi.hoisted(() => ({
	names: [] as string[],
	loaderFails: false,
}));
vi.mock("@cline/core", async () => {
	const actual =
		await vi.importActual<typeof import("@cline/core")>("@cline/core");
	return {
		...actual,
		loadAgentPluginPackages: async (
			...args: Parameters<typeof actual.loadAgentPluginPackages>
		) => {
			if (disabled.loaderFails) throw new Error("Owned discovery failure");
			return actual.loadAgentPluginPackages(...args);
		},
		resolveDisabledAgentPluginNames: () => new Set(disabled.names),
	};
});
import {
	createUserInstructionConfigService,
	loadAgentPluginPackages,
	parseAgentSkillMarkdown,
} from "@cline/core";
import manifest from "./investigation-skill-manifest.json";
import {
	inspectInvestigationSkillPack,
	INVESTIGATION_PLUGIN_NAME,
	INVESTIGATION_SKILL_NAMES,
	loadInvestigationSkills,
	selfcheckInvestigationSkills,
	verifyInvestigationSkillPack,
} from "./investigation-skills";

const source = fileURLToPath(
	new URL("../src-tauri/investigation-skills", import.meta.url),
);
let root: string, pack: string;
beforeEach(() => {
	disabled.names = [];
	disabled.loaderFails = false;
	root = mkdtempSync(join(tmpdir(), "cline-skills-"));
	pack = join(root, "installed");
	cpSync(source, pack, { recursive: true });
});
afterEach(() => rmSync(root, { recursive: true, force: true }));
const first = () => join(pack, "skills", "analyze-electron", "SKILL.md");
const inspect = () =>
	inspectInvestigationSkillPack(true, {
		installedRoot: pack,
		sourceRoot: source,
	});

describe("pinned instruction-only investigation pack", () => {
	it("degrades async loader failure to explicit unavailability without breaking the host", async () => {
		disabled.loaderFails = true;
		expect(await loadInvestigationSkills(true)).toMatchObject({
			pack: { status: "unavailable", reason: "integrity-failed", paths: [] },
			skills: [],
		});
		await expect(selfcheckInvestigationSkills()).rejects.toThrow("unavailable");
	});
	it("verifies all fixed files and exposes the complete unique skill inventory", () => {
		expect(() => verifyInvestigationSkillPack(pack)).not.toThrow();
		expect(manifest.files).toHaveLength(13);
		expect(new Set(INVESTIGATION_SKILL_NAMES).size).toBe(10);
		expect(inspect()).toMatchObject({
			status: "available",
			root: pack,
			paths: [pack],
		});
	});
	it("passes the strict portable loader without tools, code or MCP contributions", async () => {
		const report = await loadAgentPluginPackages({
			pluginPaths: [pack],
			searchPaths: [],
			disabledPluginNames: [],
		});
		expect(report.diagnostics).toEqual([]);
		expect(report.plugins).toHaveLength(1);
		expect(report.skills.map((s) => s.metadata.name).sort()).toEqual(
			[...INVESTIGATION_SKILL_NAMES].sort(),
		);
		expect(report.mcpServers).toEqual([]);
		expect(report.plugins[0]?.manifest.name).toBe(INVESTIGATION_PLUGIN_NAME);
		expect(report.plugins[0]?.manifest.extensions).toBeUndefined();
	});
	it("keeps bodies bounded, strict frontmatter valid and REA installation recipes absent", () => {
		for (const name of INVESTIGATION_SKILL_NAMES) {
			const markdown = readFileSync(
				join(pack, "skills", name, "SKILL.md"),
				"utf8",
			);
			const parsed = parseAgentSkillMarkdown(markdown, name);
			expect(parsed.metadata.name).toBe(name);
			expect(parsed.metadata.description.length).toBeGreaterThan(80);
			expect(parsed.instructions.length).toBeLessThan(12000);
			expect(parsed.instructions).not.toMatch(
				/npx\s|rea-agents@|rea\s+(?:doctor|setup|analyze-)/i,
			);
			expect(parsed.instructions).toMatch(/approv/i);
			expect(parsed.instructions).toMatch(/receipt/i);
		}
	});
	it("detects equal-length content substitution", () => {
		const bytes = readFileSync(first());
		bytes[bytes.length - 2] ^= 1;
		writeFileSync(first(), bytes);
		expect(inspect()).toMatchObject({
			status: "unavailable",
			reason: "integrity-failed",
			paths: [],
		});
	});
	it("rejects appended bytes and does not use a clean development fallback", () => {
		writeFileSync(first(), readFileSync(first(), "utf8") + "EXTRA");
		expect(inspect()).toMatchObject({
			status: "unavailable",
			reason: "integrity-failed",
			paths: [],
		});
	});
	it("rejects a missing expected file", () => {
		rmSync(first());
		expect(inspect()).toMatchObject({
			status: "unavailable",
			reason: "integrity-failed",
		});
	});
	it("rejects an unexpected MCP file", () => {
		writeFileSync(join(pack, "mcp.json"), "{}");
		expect(inspect()).toMatchObject({
			status: "unavailable",
			reason: "integrity-failed",
		});
	});
	it("rejects an unexpected directory", () => {
		mkdirSync(join(pack, "scripts"));
		expect(inspect()).toMatchObject({
			status: "unavailable",
			reason: "integrity-failed",
		});
	});
	it("rejects hard-linked instruction bytes", () => {
		linkSync(first(), join(root, "other.md"));
		expect(inspect()).toMatchObject({
			status: "unavailable",
			reason: "integrity-failed",
		});
	});
	it("rejects a redirected skill directory on Windows junctions and POSIX links", () => {
		const member = join(pack, "skills", "analyze-electron"),
			other = join(root, "other");
		cpSync(member, other, { recursive: true });
		rmSync(member, { recursive: true });
		symlinkSync(
			other,
			member,
			process.platform === "win32" ? "junction" : "dir",
		);
		expect(inspect()).toMatchObject({
			status: "unavailable",
			reason: "integrity-failed",
		});
	});
	it("rejects a broken installed-root link instead of hiding it behind source fallback", () => {
		rmSync(pack, { recursive: true });
		const other = join(root, "other");
		mkdirSync(other);
		symlinkSync(other, pack, process.platform === "win32" ? "junction" : "dir");
		rmSync(other, { recursive: true });
		expect(inspect()).toMatchObject({
			status: "unavailable",
			reason: "integrity-failed",
			paths: [],
		});
	});
	it("returns an explicit missing state without inventing skills", () => {
		expect(
			inspectInvestigationSkillPack(true, {
				installedRoot: join(root, "absent"),
				sourceRoot: join(root, "also-absent"),
			}),
		).toMatchObject({ status: "unavailable", reason: "missing", skills: [] });
	});
	it("does not expose host paths or inspect resources for remote environments", () => {
		expect(
			inspectInvestigationSkillPack(false, {
				installedRoot: pack,
				sourceRoot: source,
			}),
		).toEqual({
			status: "unavailable",
			reason: "not-local",
			paths: [],
			skills: [],
		});
	});
	it("requires both base and Windows runtime Tauri resource recipes to ship the pack", () => {
		for (const name of [
			"tauri.conf.json",
			"tauri.analysis-runtime.conf.json",
		]) {
			const config = JSON.parse(
				readFileSync(
					fileURLToPath(new URL(`../src-tauri/${name}`, import.meta.url)),
					"utf8",
				),
			);
			expect(config.bundle.resources).toContain("investigation-skills/**/*");
		}
	});
	it("exposes metadata and loads a body through the real skills executor without starting a target", async () => {
		const bundled = await loadInvestigationSkills(true);
		const service = createUserInstructionConfigService({
			skills: { directories: [], agentPluginSkills: bundled.skills },
			rules: { directories: [] },
			workflows: { directories: [] },
		});
		const before = readdirSync(pack);
		try {
			await service.start();
			expect(service.listRecords("skill")).toHaveLength(10);
			const executor = service.createSkillsExecutor!();
			expect(executor.configuredSkills?.map((s) => s.id)).toContain(
				"cline-investigation:analyze-electron",
			);
			const body = await executor(
				"cline-investigation:analyze-electron",
				undefined,
				{} as Parameters<typeof executor>[2],
			);
			expect(body).toContain("applicationGraph");
			expect(body).toContain("not a complete cross-module taint solver");
			expect(service.listRuntimeCommands().map((s) => s.name)).toContain(
				"analyze-electron",
			);
			expect(
				service.resolveRuntimeSlashCommand("/analyze-electron owned", {
					expandSkillCommands: false,
				}),
			).toBe("/analyze-electron owned");
			expect(
				service.resolveRuntimeSlashCommand("/analyze-electron owned"),
			).toContain("applicationGraph");
			expect(readdirSync(pack)).toEqual(before);
		} finally {
			service.stop();
		}
	});
	it("preserves an existing bare command while the qualified bundled skill remains loadable", async () => {
		const directory = join(root, "user-skills");
		const skill = join(directory, "analyze-electron");
		mkdirSync(skill, { recursive: true });
		writeFileSync(
			join(skill, "SKILL.md"),
			"---\nname: analyze-electron\ndescription: Existing owned user guide.\n---\nUSER_GUIDE_NOT_SHIPPED\n",
		);
		const bundled = await loadInvestigationSkills(true);
		const service = createUserInstructionConfigService({
			skills: { directories: [directory], agentPluginSkills: bundled.skills },
			rules: { directories: [] },
			workflows: { directories: [] },
		});
		try {
			await service.start();
			expect(service.listRecords("skill")).toHaveLength(11);
			expect(
				service.resolveRuntimeSlashCommand("/analyze-electron owned"),
			).toContain("USER_GUIDE_NOT_SHIPPED");
			const executor = service.createSkillsExecutor!();
			expect(
				await executor(
					"cline-investigation:analyze-electron",
					undefined,
					{} as Parameters<typeof executor>[2],
				),
			).toContain("applicationGraph");
		} finally {
			service.stop();
		}
	});
	it("dispatches the real selfcheck flag before creating a profile, Hub or listener", () => {
		const profile = join(root, "isolated-selfcheck");
		const discovery = join(profile, "hub.json");
		const stdout = execFileSync(
			"bun",
			[
				fileURLToPath(new URL("./index.ts", import.meta.url)),
				"--cline-investigation-skills-selfcheck",
			],
			{
				timeout: 20000,
				maxBuffer: 65536,
				encoding: "utf8",
				cwd: root,
				env: {
					PATH: process.env.PATH,
					SystemRoot: process.env.SystemRoot,
					TEMP: process.env.TEMP,
					TMP: process.env.TMP,
					CLINE_DIR: profile,
					CLINE_DATA_DIR: join(profile, "data"),
					CLINE_HUB_DISCOVERY_PATH: discovery,
				},
			},
		);
		expect(JSON.parse(stdout)).toMatchObject({
			status: "passed",
			loadedInstructions: 10,
			instructionOnly: true,
		});
		expect(stdout).not.toContain('"type":"ready"');
		expect(existsSync(discovery)).toBe(false);
		expect(existsSync(profile)).toBe(false);
	});
	it("selfchecks all bundled bodies with no target/provider/MCP and honors disablement", async () => {
		expect(await selfcheckInvestigationSkills()).toMatchObject({
			status: "passed",
			loadedInstructions: 10,
			instructionOnly: true,
			providerCalls: 0,
			mcpServers: 0,
			targetExecuted: false,
		});
		disabled.names = [INVESTIGATION_PLUGIN_NAME];
		expect(await selfcheckInvestigationSkills()).toMatchObject({
			status: "disabled",
			skills: [],
		});
	});
	it("honors the existing portable-plugin disable setting without touching packaged files", async () => {
		disabled.names = [INVESTIGATION_PLUGIN_NAME];
		const before = readFileSync(first());
		const result = await loadInvestigationSkills(true);
		expect(result.pack.status).toBe("available");
		expect(result.skills).toEqual([]);
		expect(readFileSync(first())).toEqual(before);
		expect(existsSync(join(pack, "mcp.json"))).toBe(false);
	});
});
