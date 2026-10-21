import { createHash } from "node:crypto";
import {
	existsSync,
	fstatSync,
	lstatSync,
	openSync,
	closeSync,
	readSync,
	readdirSync,
} from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
	createUserInstructionConfigService,
	loadAgentPluginPackages,
	resolveDisabledAgentPluginNames,
} from "@cline/core";
import manifest from "./investigation-skill-manifest.json";

export const INVESTIGATION_PLUGIN_NAME = manifest.pluginName;
export const INVESTIGATION_SKILL_NAMES = Object.freeze([...manifest.skills]);
export type InvestigationSkillPackStatus =
	| {
			status: "available";
			root: string;
			paths: string[];
			skills: readonly string[];
	  }
	| {
			status: "unavailable";
			reason: "not-local" | "missing" | "integrity-failed";
			paths: string[];
			skills: readonly string[];
	  };

/** Verify only fixed host-owned instruction resources. Never execute a member. */
export function verifyInvestigationSkillPack(root: string): void {
	const expected = new Map(manifest.files.map((f) => [f.path, f]));
	const directories = new Set<string>();
	for (const path of expected.keys()) {
		const parts = path.split("/");
		for (let i = 1; i < parts.length; i++)
			directories.add(parts.slice(0, i).join("/"));
	}
	let entries = 0;
	const found = new Set<string>();
	function visit(relative: string) {
		const path = relative ? join(root, relative) : root;
		const info = lstatSync(path);
		if (info.isSymbolicLink() || !info.isDirectory())
			throw new Error("Skill pack directory redirected");
		for (const entry of readdirSync(path, { withFileTypes: true })) {
			if (++entries > 64) throw new Error("Skill pack entry budget exceeded");
			const member = relative ? `${relative}/${entry.name}` : entry.name;
			if (entry.isDirectory() && directories.has(member)) {
				visit(member);
				continue;
			}
			const record = expected.get(member);
			if (!record || !entry.isFile() || entry.isSymbolicLink())
				throw new Error("Unexpected skill pack member");
			const memberPath = join(root, member);
			const stat = lstatSync(memberPath);
			if (
				!stat.isFile() ||
				stat.isSymbolicLink() ||
				stat.size !== record.bytes ||
				stat.nlink !== 1
			)
				throw new Error("Skill pack member identity mismatch");
			const fd = openSync(memberPath, "r");
			try {
				const opened = fstatSync(fd);
				if (
					!opened.isFile() ||
					opened.dev !== stat.dev ||
					opened.ino !== stat.ino ||
					opened.size !== record.bytes ||
					opened.nlink !== 1
				)
					throw new Error("Skill pack member redirected");
				const bytes = Buffer.alloc(record.bytes + 1);
				let total = 0,
					read = 0;
				do {
					read = readSync(fd, bytes, total, bytes.length - total, total);
					total += read;
				} while (read > 0 && total < bytes.length);
				if (
					total !== record.bytes ||
					createHash("sha256")
						.update(bytes.subarray(0, total))
						.digest("hex") !== record.sha256
				)
					throw new Error("Skill pack integrity mismatch");
			} finally {
				closeSync(fd);
			}
			found.add(member);
		}
	}
	visit("");
	if (found.size !== expected.size)
		throw new Error("Skill pack member missing");
}

/** Installed resources take precedence; an invalid installation never falls back. */
export function inspectInvestigationSkillPack(
	local: boolean,
	options: { installedRoot?: string; sourceRoot?: string } = {},
): InvestigationSkillPackStatus {
	if (!local)
		return {
			status: "unavailable",
			reason: "not-local",
			paths: [],
			skills: [],
		};
	const installedRoot =
		options.installedRoot ??
		join(dirname(process.execPath), "investigation-skills");
	const modulePath = fileURLToPath(import.meta.url);
	const sourceRoot =
		options.sourceRoot ??
		(existsSync(modulePath)
			? fileURLToPath(
					new URL("../src-tauri/investigation-skills", import.meta.url),
				)
			: undefined);
	// lstat also sees broken links; never hide a redirected installation with a dev fallback.
	let installedPresent = true;
	try {
		installedPresent = !!lstatSync(installedRoot, { throwIfNoEntry: false });
	} catch {
		/* An inaccessible installation must fail closed below. */
	}
	const root = installedPresent ? installedRoot : sourceRoot;
	if (!root || (!installedPresent && !existsSync(root)))
		return { status: "unavailable", reason: "missing", paths: [], skills: [] };
	try {
		verifyInvestigationSkillPack(root);
		return {
			status: "available",
			root,
			paths: [root],
			skills: INVESTIGATION_SKILL_NAMES,
		};
	} catch {
		return {
			status: "unavailable",
			reason: "integrity-failed",
			paths: [],
			skills: [],
		};
	}
}

/** Namespaced portable skills use the existing plugin disable setting and loader. */
export async function loadInvestigationSkills(local: boolean) {
	const pack = inspectInvestigationSkillPack(local);
	if (pack.status !== "available") return { pack, skills: [] };
	try {
		const loaded = await loadAgentPluginPackages({
			pluginPaths: pack.paths,
			searchPaths: [],
			disabledPluginNames: [...resolveDisabledAgentPluginNames()],
		});
		if (
			loaded.diagnostics.some((d) => d.level === "error") ||
			loaded.mcpServers.length
		)
			throw new Error("Bundled instruction-only skill pack invalid");
		// A normal update/removal during async discovery must not leave a stale catalog.
		verifyInvestigationSkillPack(pack.root);
		return { pack, skills: loaded.skills };
	} catch {
		return {
			pack: {
				status: "unavailable",
				reason: "integrity-failed",
				paths: [],
				skills: [],
			} as InvestigationSkillPackStatus,
			skills: [],
		};
	}
}

/** Fixed instruction-read selfcheck; no provider, target, server or installation. */
export async function selfcheckInvestigationSkills() {
	const loaded = await loadInvestigationSkills(true);
	if (loaded.pack.status !== "available")
		throw new Error(
			`Investigation skill pack unavailable: ${loaded.pack.reason}`,
		);
	if (!loaded.skills.length)
		return {
			status: "disabled",
			plugin: INVESTIGATION_PLUGIN_NAME,
			skills: [],
			instructionOnly: true,
		};
	const service = createUserInstructionConfigService({
		skills: { directories: [], agentPluginSkills: loaded.skills },
		rules: { directories: [] },
		workflows: { directories: [] },
	});
	try {
		await service.start();
		const records = service.listRecords("skill");
		if (records.length !== INVESTIGATION_SKILL_NAMES.length)
			throw new Error("Investigation skill metadata incomplete");
		const executor = service.createSkillsExecutor!();
		for (const name of INVESTIGATION_SKILL_NAMES) {
			const body = await executor(
				`${INVESTIGATION_PLUGIN_NAME}:${name}`,
				undefined,
				{} as Parameters<typeof executor>[2],
			);
			if (
				typeof body !== "string" ||
				!body.includes("<command-instructions>") ||
				!body.includes("receipt")
			)
				throw new Error("Investigation skill instruction read failed");
		}
		return {
			status: "passed",
			plugin: INVESTIGATION_PLUGIN_NAME,
			skills: [...INVESTIGATION_SKILL_NAMES],
			loadedInstructions: records.length,
			instructionOnly: true,
			mcpServers: 0,
			providerCalls: 0,
			targetExecuted: false,
		};
	} finally {
		service.stop();
	}
}
