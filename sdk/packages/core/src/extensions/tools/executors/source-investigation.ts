import * as fs from "node:fs/promises";
import * as path from "node:path";
import ts from "typescript";
import { type AnalysisResult, digest } from "../../../analysis/contracts";
import { analyzeSources, type SourceArtifact } from "../../../analysis/parser";
import { WorkflowQuerySchema } from "../investigation-workflows-schema";
import {
	candidateHash,
	readCandidateFile,
	rejectCandidateLinks,
} from "./candidate-files";

const sourceName = /\.(?:[cm]?[jt]s|[jt]sx)$/i;
const ignored = new Set(["node_modules", ".git", "dist", "build", ".cline"]);
/** Owned parser; never import/evaluate target code. Exactly bounded file/entry/byte inventory. */
export async function collectWorkflowSources(
	target: string,
	signal?: AbortSignal,
) {
	await rejectCandidateLinks(target);
	const sources: SourceArtifact[] = [],
		limitations: string[] = [];
	let entries = 0,
		total = 0;
	const rootInfo = await fs.lstat(target),
		root = rootInfo.isDirectory() ? target : path.dirname(target);
	const visit = async (file: string, depth: number): Promise<void> => {
		signal?.throwIfAborted();
		if (++entries > 4096)
			throw new Error("Source entry budget exceeded; narrow the target");
		const info = await fs.lstat(file);
		if (info.isSymbolicLink())
			throw new Error("Source workflow rejects symbolic links");
		if (info.isDirectory()) {
			if (depth > 8) throw new Error("Source depth budget exceeded");
			const names: string[] = [];
			const directory = await fs.opendir(file);
			for await (const entry of directory) {
				signal?.throwIfAborted();
				if (names.length >= 4096)
					throw new Error("Source directory entry budget exceeded");
				names.push(entry.name);
			}
			for (const name of names.sort()) {
				if (ignored.has(name)) {
					limitations.push(
						`Excluded directory: ${path.relative(root, path.join(file, name))}`,
					);
					continue;
				}
				await visit(path.join(file, name), depth + 1);
			}
		} else if (info.isFile() && sourceName.test(file)) {
			if (sources.length >= 128) throw new Error("Source file budget exceeded");
			const bytes = await readCandidateFile(file, 1024 * 1024, signal);
			total += bytes.length;
			if (total > 8 * 1024 * 1024)
				throw new Error("Source aggregate byte budget exceeded");
			sources.push({
				path: path.relative(root, file).split(path.sep).join("/"),
				sha256: candidateHash(bytes),
				bytes: bytes.length,
				source: new TextDecoder("utf-8", {
					fatal: true,
					ignoreBOM: true,
				}).decode(bytes),
			});
		} else if (!info.isFile())
			throw new Error("Source workflow accepts regular files/directories only");
	};
	await visit(target, 0);
	if (!sources.length)
		throw new Error(
			"No supported JS/TS sources; select a JS/TS file or directory",
		);
	return { sources, limitations: [...new Set(limitations)].slice(0, 80) };
}
function selectedReport(
	report: AnalysisResult,
	operation: string,
	options: unknown,
) {
	const q = WorkflowQuerySchema.parse(options ?? {});
	let selected = report.facts;
	if (operation === "trace_source_symbol" || operation === "explain_behavior") {
		if (!q.symbol) throw new Error("Exact workflow_query.symbol required");
		const matches = report.facts.filter(
			(f) =>
				["function", "semantic-function"].includes(f.kind) &&
				f.value === q.symbol,
		);
		if (
			new Set(
				matches.map(
					(f) => `${f.location.path}:${f.location.line}:${f.location.column}`,
				),
			).size !== 1
		)
			throw new Error(
				`Expected one exact source function; found ${matches.length}`,
			);
		const ids = new Set(matches.map((f) => f.id));
		for (let depth = 0; depth < q.max_depth; depth++) {
			const next = new Set(ids);
			for (const e of report.edges)
				if (ids.has(e.source) || ids.has(e.target)) {
					next.add(e.source);
					next.add(e.target);
					if (next.size > 200) break;
				}
			if (next.size > 200) break;
			if (next.size === ids.size) break;
			for (const id of next) ids.add(id);
		}
		selected = report.facts.filter((f) => ids.has(f.id));
	} else if (operation === "trace_electron_ipc")
		selected = report.facts.filter((f) =>
			[
				"ipc-send",
				"ipc-handler",
				"preload-api",
				"preload-call",
				"preload-member",
				"preload-unresolved",
			].includes(f.kind),
		);
	else if (operation === "audit_preload_bridge")
		selected = report.facts.filter(
			(f) =>
				f.kind.startsWith("preload") ||
				f.kind === "configuration" ||
				f.kind === "dynamic",
		);
	else if (operation === "map_attack_surface")
		selected = report.facts.filter((f) =>
			[
				"entrypoint",
				"endpoint",
				"resolved-endpoint",
				"export",
				"ipc-handler",
				"preload-api",
				"preload-member",
				"configuration",
				"native-addon",
				"dynamic",
			].includes(f.kind),
		);
	else if (operation === "compare_public_api")
		selected = report.facts.filter((f) => f.kind === "export");
	const facts = selected.slice(0, q.max_results),
		ids = new Set(facts.map((f) => f.id));
	const edges = report.edges
		.filter((e) => ids.has(e.source) && ids.has(e.target))
		.slice(0, 400);
	return {
		facts,
		edges,
		truncated: selected.length > facts.length,
		sourceStatus: report.status,
	};
}
function publicDeclarations(sources: SourceArtifact[]) {
	const declarations: {
		key: string;
		path: string;
		line: number;
		sha256: string;
	}[] = [];
	for (const source of sources) {
		const file = ts.createSourceFile(
			source.path,
			source.source,
			ts.ScriptTarget.Latest,
			true,
		);
		for (const statement of file.statements) {
			const modifiers = ts.canHaveModifiers(statement)
				? ts.getModifiers(statement)
				: undefined;
			const exported = modifiers?.some(
				(m) => m.kind === ts.SyntaxKind.ExportKeyword,
			);
			let names: string[] = [];
			if (ts.isExportDeclaration(statement) || ts.isExportAssignment(statement))
				names = [
					ts.isExportAssignment(statement)
						? "default"
						: statement.getText(file),
				];
			else if (exported) {
				if (modifiers?.some((m) => m.kind === ts.SyntaxKind.DefaultKeyword))
					names = ["default"];
				else if (ts.isVariableStatement(statement))
					names = statement.declarationList.declarations.map((d) =>
						d.name.getText(file),
					);
				else if ("name" in statement && statement.name)
					names = [(statement.name as ts.Node).getText(file)];
			}
			for (const name of names) {
				if (declarations.length >= 8000 || name.length > 4096)
					throw new Error("Public declaration budget exceeded");
				declarations.push({
					key: `${sources.length === 1 ? "<entry>" : source.path}:${name}`,
					path: source.path,
					line:
						file.getLineAndCharacterOfPosition(statement.getStart(file)).line +
						1,
					sha256: source.sha256,
				});
			}
		}
	}
	return declarations;
}
function functionSelection(sources: SourceArtifact[], symbol: string) {
	const matches: {
		source: SourceArtifact;
		file: ts.SourceFile;
		node: ts.FunctionDeclaration;
	}[] = [];
	for (const source of sources) {
		const file = ts.createSourceFile(
			source.path,
			source.source,
			ts.ScriptTarget.Latest,
			true,
		);
		const visit = (node: ts.Node) => {
			if (ts.isFunctionDeclaration(node) && node.name?.text === symbol)
				matches.push({ source, file, node });
			ts.forEachChild(node, visit);
		};
		visit(file);
	}
	if (matches.length !== 1)
		throw new Error("Expected one exact JS/TS function declaration");
	const { source, file, node } = matches[0],
		text = node.getText(file),
		location = file.getLineAndCharacterOfPosition(node.getStart(file));
	return {
		path: source.path,
		sha256: source.sha256,
		line: location.line + 1,
		column: location.character + 1,
		text: text.slice(0, 16384),
		truncated: text.length > 16384,
	};
}
export async function sourceInvestigation(
	input: {
		operation: string;
		target?: string;
		compare_target?: string;
		workflow_query?: unknown;
	},
	signal?: AbortSignal,
) {
	if (!input.target) throw new Error("Source target required");
	const inventory = await collectWorkflowSources(input.target, signal);
	signal?.throwIfAborted();
	const report = analyzeSources(inventory.sources, inventory.limitations);
	const evidence = selectedReport(
		report,
		input.operation,
		input.workflow_query,
	);
	let comparison: unknown;
	if (input.operation === "compare_public_api") {
		if (!input.compare_target)
			throw new Error("compare_public_api requires compare_target");
		const second = await collectWorkflowSources(input.compare_target, signal);
		signal?.throwIfAborted();
		const right = analyzeSources(second.sources, second.limitations),
			q = WorkflowQuerySchema.parse(input.workflow_query ?? {});
		const leftDeclarations = publicDeclarations(inventory.sources),
			rightDeclarations = publicDeclarations(second.sources);
		const a = new Set(leftDeclarations.map((d) => d.key)),
			b = new Set(rightDeclarations.map((d) => d.key)),
			added = [...b].filter((x) => !a.has(x)),
			removed = [...a].filter((x) => !b.has(x));
		comparison = {
			added: added.slice(0, q.max_results),
			removed: removed.slice(0, q.max_results),
			truncated: added.length > q.max_results || removed.length > q.max_results,
			leftDeclarations: leftDeclarations.slice(0, q.max_results),
			rightDeclarations: rightDeclarations.slice(0, q.max_results),
			rightArtifacts: right.artifacts,
			rightLimitations: right.limitations,
		};
	}
	return {
		schemaVersion: 1,
		operation: input.operation,
		status: "partial",
		adapter: "js-ts-owned-syntax/v1",
		effect: "read",
		evidence,
		comparison,
		selectedFunction: ["explain_behavior", "trace_source_symbol"].includes(
			input.operation,
		)
			? functionSelection(
					inventory.sources,
					WorkflowQuerySchema.parse(input.workflow_query ?? {}).symbol!,
				)
			: undefined,
		artifacts: report.artifacts,
		inputFingerprint: digest(report.artifacts),
		observedExecution: false,
		limitations: [
			...report.limitations,
			"JS/TS syntax and bounded declared static relationships only. No target code executes, dynamic dispatch/IPC execution proof, vulnerability verdict, whole-program flow, or behavior equivalence.",
			"Explanation is selected function evidence and relationships, not a speculative natural-language behavioral conclusion.",
			"Public API comparison covers syntactic export declarations, not types, resolved re-exports or ABI compatibility. Other language adapters are not implied.",
		],
	};
}
export async function dependencyInventory(
	target: string,
	signal?: AbortSignal,
) {
	const bytes = await readCandidateFile(target, 1024 * 1024, signal);
	const doc: unknown = JSON.parse(
		new TextDecoder("utf-8", { fatal: true }).decode(bytes),
	);
	if (!doc || typeof doc !== "object" || Array.isArray(doc))
		throw new Error("Expected package.json object");
	const rows: { group: string; name: string; declared: string }[] = [];
	for (const group of [
		"dependencies",
		"devDependencies",
		"optionalDependencies",
		"peerDependencies",
	]) {
		const values = (doc as Record<string, unknown>)[group];
		if (values === undefined) continue;
		if (!values || typeof values !== "object" || Array.isArray(values))
			throw new Error("Invalid dependency group");
		for (const [name, value] of Object.entries(values)) {
			if (
				rows.length >= 1000 ||
				name.length > 214 ||
				typeof value !== "string" ||
				value.length > 1024
			)
				throw new Error("Dependency inventory budget/type exceeded");
			rows.push({ group, name, declared: value });
		}
	}
	return {
		status: "partial",
		effect: "read",
		inputSha256: candidateHash(bytes),
		declared: rows,
		resolvedVersions: "not-established",
		advisoryMatches: [],
		riskVerdict: "unknown",
		limitations: [
			"package.json declarations only, not lockfile resolution or verified advisory matching. No network request, install, script execution or clean-risk conclusion.",
		],
	};
}
