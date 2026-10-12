import ts from "typescript";
import { analyzeLocalSemantics } from "./semantic";
import { sourceMapLocations } from "./source-maps";
import path from "node:path";
import {
	ANALYSIS_PROFILE,
	LIMITS,
	type AnalysisFact,
	type AnalysisResult,
	digest,
} from "./contracts";

export type SourceArtifact = {
	path: string;
	sha256: string;
	bytes: number;
	source: string;
};
/** Parses syntax only. Never imports, evaluates, transpiles or executes target source. */
export function analyzeSources(
	sources: SourceArtifact[],
	partial: string[] = [],
): AnalysisResult {
	const facts: AnalysisFact[] = [],
		limitations = [...partial];
	const artifacts: AnalysisResult["artifacts"] = [];
	const semanticEdges: AnalysisResult["edges"] = [];
	let nodes = 0,
		stopped = false;
	const add = (
		source: SourceArtifact,
		file: ts.SourceFile,
		node: ts.Node,
		kind: AnalysisFact["kind"],
		value: string,
		confidence: AnalysisFact["confidence"] = "observed",
		notes: string[] = [],
	) => {
		if (facts.length >= LIMITS.facts) {
			stopped = true;
			return;
		}
		const loc = file.getLineAndCharacterOfPosition(node.getStart(file));
		const data = {
			kind,
			value: value.slice(0, 1000),
			confidence,
			authority: "shipped-artifact" as const,
			location: {
				path: source.path,
				sha256: source.sha256,
				line: loc.line + 1,
				column: loc.character + 1,
			},
			limitations: notes,
		};
		const fact: AnalysisFact = {
			id: `ev_${digest({ profile: ANALYSIS_PROFILE, parserVersion: ts.version, ...data })}`,
			...data,
		};
		facts.push(fact);
		return fact;
	};
	const literal = (n?: ts.Node) =>
		n && (ts.isStringLiteral(n) || ts.isNoSubstitutionTemplateLiteral(n))
			? n.text
			: undefined;
	for (const source of sources) {
		if (stopped) break;
		if (source.path.endsWith(".map")) {
			artifacts.push({
				path: source.path,
				sha256: source.sha256,
				bytes: source.bytes,
				role: "source-map",
			});
			const mapFile = ts.createSourceFile(
				source.path,
				"{}",
				ts.ScriptTarget.Latest,
				true,
			);
			try {
				const records = sourceMapLocations(
					source.source,
					LIMITS.facts - facts.length,
				);
				for (const record of records.locations) {
					const value = JSON.stringify(record);
					if (value.length > 1000) {
						limitations.push(
							`Source-map label too long for retained evidence: ${source.path}`,
						);
						continue;
					}
					add(
						source,
						mapFile,
						mapFile,
						"source-map-location",
						value,
						"derived",
						[
							"Untrusted source-map declaration; original labels are not opened or executed. Embedded source hash is not execution proof.",
						],
					);
				}
				if (records.partial)
					limitations.push(`Source map coverage incomplete: ${source.path}`);
			} catch {
				limitations.push(`Unsupported/malformed source map: ${source.path}`);
			}
			continue;
		}
		if (source.path.endsWith(".json")) {
			artifacts.push({
				path: source.path,
				sha256: source.sha256,
				bytes: source.bytes,
				role: "package-metadata",
			});
			try {
				const p = JSON.parse(source.source);
				const file = ts.createSourceFile(
					source.path,
					"{}",
					ts.ScriptTarget.Latest,
					true,
				);
				for (const key of ["main", "module", "browser"])
					if (typeof p[key] === "string")
						add(source, file, file, "entrypoint", p[key], "observed", [
							"Declared metadata; execution and resolved destination unverified.",
						]);
			} catch {
				limitations.push(`Invalid package metadata: ${source.path}`);
			}
			continue;
		}
		const file = ts.createSourceFile(
			source.path,
			source.source,
			ts.ScriptTarget.Latest,
			true,
			/\.[jt]sx$/.test(source.path)
				? ts.ScriptKind.TSX
				: /\.[cm]?ts$/.test(source.path)
					? ts.ScriptKind.TS
					: ts.ScriptKind.JS,
		);
		const errors =
			(file as ts.SourceFile & { parseDiagnostics?: ts.Diagnostic[] })
				.parseDiagnostics ?? [];
		if (errors.length)
			limitations.push(
				`Parse diagnostics in ${source.path}; recovered syntax is partial.`,
			);
		const declared = new Set<string>();
		const ipcAliases = new Map<string, string>(),
			contextAliases = new Set<string>();
		// Only unshadowed top-level ES imports are treated as Electron candidates.
		for (const statement of file.statements) {
			if (
				ts.isImportDeclaration(statement) &&
				literal(statement.moduleSpecifier) === "electron"
			) {
				const bindings = statement.importClause?.namedBindings;
				if (bindings && ts.isNamedImports(bindings))
					for (const e of bindings.elements) {
						const imported = e.propertyName?.text ?? e.name.text;
						if (["ipcMain", "ipcRenderer"].includes(imported))
							ipcAliases.set(e.name.text, imported);
						if (imported === "contextBridge") contextAliases.add(e.name.text);
					}
			}
		}
		const ownedBindings = new Set<ts.Node>();
		for (const statement of file.statements)
			if (ts.isVariableStatement(statement)) {
				for (const d of statement.declarationList.declarations) {
					if (
						!ts.isObjectBindingPattern(d.name) ||
						!d.initializer ||
						!ts.isCallExpression(d.initializer) ||
						!ts.isIdentifier(d.initializer.expression) ||
						d.initializer.expression.text !== "require" ||
						literal(d.initializer.arguments[0]) !== "electron"
					)
						continue;
					for (const binding of d.name.elements) {
						if (
							!ts.isIdentifier(binding.name) ||
							binding.dotDotDotToken ||
							binding.initializer
						)
							continue;
						const imported =
							binding.propertyName && ts.isIdentifier(binding.propertyName)
								? binding.propertyName.text
								: binding.name.text;
						if (["ipcMain", "ipcRenderer"].includes(imported)) {
							ipcAliases.set(binding.name.text, imported);
							ownedBindings.add(binding);
						} else if (imported === "contextBridge") {
							contextAliases.add(binding.name.text);
							ownedBindings.add(binding);
						}
					}
				}
			}
		artifacts.push({
			path: source.path,
			sha256: source.sha256,
			bytes: source.bytes,
			role: contextAliases.size
				? "preload-candidate"
				: [...ipcAliases.values()].includes("ipcMain")
					? "main-candidate"
					: [...ipcAliases.values()].includes("ipcRenderer")
						? "renderer-candidate"
						: "source",
		});
		add(source, file, file, "module", source.path);
		// Shadowing anywhere is conservatively unresolved (not a complete lexical resolver).
		const collect = (n: ts.Node) => {
			if (++nodes > LIMITS.nodes) {
				stopped = true;
				return;
			}
			if (
				(ts.isParameter(n) ||
					ts.isVariableDeclaration(n) ||
					ts.isFunctionDeclaration(n) ||
					ts.isClassDeclaration(n)) &&
				n.name
			) {
				if (ts.isIdentifier(n.name)) declared.add(n.name.text);
				else if (
					ts.isObjectBindingPattern(n.name) ||
					ts.isArrayBindingPattern(n.name)
				)
					for (const e of n.name.elements)
						if (
							ts.isBindingElement(e) &&
							ts.isIdentifier(e.name) &&
							!ownedBindings.has(e)
						)
							declared.add(e.name.text);
			}
			if (
				ts.isBinaryExpression(n) &&
				n.operatorToken.kind >= ts.SyntaxKind.FirstAssignment &&
				n.operatorToken.kind <= ts.SyntaxKind.LastAssignment &&
				ts.isIdentifier(n.left)
			)
				declared.add(n.left.text);
			if (ts.isImportDeclaration(n)) {
				const c = n.importClause;
				if (c?.name) declared.add(c.name.text);
				if (c?.namedBindings && ts.isNamespaceImport(c.namedBindings))
					declared.add(c.namedBindings.name.text);
				if (c?.namedBindings && ts.isNamedImports(c.namedBindings))
					for (const e of c.namedBindings.elements)
						if (
							!ipcAliases.has(e.name.text) &&
							!contextAliases.has(e.name.text)
						)
							declared.add(e.name.text);
			}
			ts.forEachChild(n, collect);
		};
		collect(file);
		if (stopped) break;
		// A locally shadowed require cannot establish CommonJS Electron identity.
		if (declared.has("require"))
			for (const b of ownedBindings) {
				const binding = b as ts.BindingElement;
				if (ts.isIdentifier(binding.name)) {
					ipcAliases.delete(binding.name.text);
					contextAliases.delete(binding.name.text);
				}
			}
		const visit = (n: ts.Node) => {
			if (stopped) return;
			if (++nodes > LIMITS.nodes) {
				stopped = true;
				return;
			}
			if (ts.isImportDeclaration(n)) {
				const v = literal(n.moduleSpecifier);
				if (v !== undefined)
					add(
						source,
						file,
						n,
						v.endsWith(".node") ? "native-addon" : "import",
						v,
					);
			}
			if (ts.isExportDeclaration(n) || ts.isExportAssignment(n))
				add(
					source,
					file,
					n,
					"export",
					ts.isExportDeclaration(n)
						? (literal(n.moduleSpecifier) ??
								n.exportClause?.getText(file) ??
								"*")
						: "default",
				);
			if (ts.isFunctionDeclaration(n) && n.name)
				add(source, file, n, "function", n.name.text);
			if (ts.isCallExpression(n)) {
				const expr = n.expression,
					arg = literal(n.arguments[0]);
				if (
					(ts.isIdentifier(expr) &&
						expr.text === "require" &&
						!declared.has("require")) ||
					expr.kind === ts.SyntaxKind.ImportKeyword
				) {
					add(
						source,
						file,
						n,
						arg === undefined
							? "dynamic"
							: arg.endsWith(".node")
								? "native-addon"
								: "import",
						arg ?? "Unresolved dynamic module expression",
					);
				} else if (
					ts.isPropertyAccessExpression(expr) &&
					ts.isIdentifier(expr.expression)
				) {
					const owner = expr.expression.text,
						member = expr.name.text;
					if (
						!declared.has(owner) &&
						ipcAliases.has(owner) &&
						((ipcAliases.get(owner) === "ipcMain" &&
							["handle", "on", "once"].includes(member)) ||
							(ipcAliases.get(owner) === "ipcRenderer" &&
								["send", "invoke", "sendSync"].includes(member)))
					) {
						add(
							source,
							file,
							n,
							arg === undefined
								? "dynamic"
								: ipcAliases.get(owner) === "ipcMain"
									? "ipc-handler"
									: "ipc-send",
							arg ?? "Unresolved IPC channel",
							"derived",
							[
								"Syntactic Electron import candidate; execution and handler reachability unverified.",
							],
						);
					} else if (
						!declared.has(owner) &&
						contextAliases.has(owner) &&
						member === "exposeInMainWorld"
					)
						add(
							source,
							file,
							n,
							arg === undefined ? "dynamic" : "preload-api",
							arg ?? "Unresolved exposed API",
							"derived",
							["Syntactic preload exposure; runtime context unverified."],
						);
				}
				if (
					ts.isIdentifier(expr) &&
					expr.text === "fetch" &&
					!declared.has("fetch")
				)
					add(
						source,
						file,
						n,
						arg === undefined ? "dynamic" : "endpoint",
						arg ?? "Unresolved fetch URL",
						"derived",
						["Syntactic global-fetch candidate; no request was sent."],
					);
				if (ts.isIdentifier(expr) && !["require", "fetch"].includes(expr.text))
					add(source, file, n, "call", expr.text, "observed", [
						"Call syntax only; callee identity and data flow unresolved.",
					]);
			}
			ts.forEachChild(n, visit);
		};
		visit(file);
		if (!stopped) {
			const semantic = analyzeLocalSemantics(
				file,
				source,
				(node, kind, value, notes) =>
					add(source, file, node, kind, value, "derived", notes),
				LIMITS.facts - semanticEdges.length,
			);
			semanticEdges.push(...semantic.edges);
			nodes += semantic.visits;
			if (semantic.exhausted || nodes > LIMITS.nodes) stopped = true;
		}
	}
	if (stopped)
		limitations.push(
			"AST node or finding budget reached; remaining syntax was not inspected.",
		);
	const edges: AnalysisResult["edges"] = [...semanticEdges];
	const modules = new Map(
		facts.filter((f) => f.kind === "module").map((f) => [f.value, f]),
	);
	for (const f of facts.filter(
		(f) => f.kind === "import" && f.value.startsWith("."),
	)) {
		const base = path.posix.normalize(
			path.posix.join(path.posix.dirname(f.location.path), f.value),
		);
		const matches = [
			base,
			...[
				".js",
				".ts",
				".mjs",
				".cjs",
				".tsx",
				".jsx",
				"/index.js",
				"/index.ts",
			].map((e) => base + e),
		].filter((p) => modules.has(p));
		if (matches.length === 1 && edges.length < LIMITS.facts)
			edges.push({
				source: f.id,
				target: modules.get(matches[0])!.id,
				kind: "imports",
				confidence: "derived",
				limitations: [
					"Literal relative-path candidate; package exports and runtime resolution not modeled.",
				],
			});
	}
	const sends = facts.filter((f) => f.kind === "ipc-send"),
		handlers = facts.filter((f) => f.kind === "ipc-handler");
	const channels = new Map<string, AnalysisFact[]>();
	for (const handler of handlers) {
		const items = channels.get(handler.value) ?? [];
		items.push(handler);
		channels.set(handler.value, items);
	}

	ipcEdges: for (const send of sends)
		for (const handler of channels.get(send.value) ?? []) {
			if (edges.length >= LIMITS.facts) break ipcEdges;
			edges.push({
				source: send.id,
				target: handler.id,
				kind: "ipc-candidate",
				confidence: "derived",
				limitations: [
					"Equal literal channel names; not proof of delivery, unique routing, or execution.",
				],
			});
		}
	if (edges.length >= LIMITS.facts)
		limitations.push(
			"Relationship budget reached; graph coverage may be incomplete.",
		);
	const status = limitations.length ? "partial" : "completed";
	return {
		profile: ANALYSIS_PROFILE,
		parserVersion: ts.version,
		status,
		artifacts,
		facts,
		edges,
		limitations: [
			...limitations.slice(0, 90),
			"Bounded syntax, local symbol/value reduction and pure-return call candidates only; no complete alias analysis or interprocedural recovery, universal deobfuscation or execution proof.",
			"Source-map labels are untrusted declarations; unpacked ASAR entries, dynamic imports and native addons are not executed or decompiled.",
		],
		counters: {
			entries: sources.length,
			bytes: sources.reduce((n, s) => n + s.bytes, 0),
			nodes,
		},
	};
}
