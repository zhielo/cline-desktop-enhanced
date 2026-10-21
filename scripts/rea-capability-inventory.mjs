/** Development-only audit. Reads pinned source, never installs/runs REA or a provider. */
import { readFileSync, readdirSync, existsSync, writeFileSync } from "node:fs";
import { resolve, dirname, relative, posix } from "node:path";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
const repo = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const require = createRequire(resolve(repo, "sdk/packages/core/package.json"));
const ts = require("typescript");
const base = process.env.CLINE_SEMANTIC_REFERENCE_ROOT;
if (!base)
	throw Error(
		"CLINE_SEMANTIC_REFERENCE_ROOT must identify the pinned development checkout",
	);
const root = resolve(base),
	cache = new Map();
if (
	execFileSync("git", ["-C", root, "rev-parse", "HEAD"], {
		encoding: "utf8",
	}).trim() !== "d0067ba34a39ea47dd7e11bb2e6169bc0938cc3f"
)
	throw Error("Reference revision is not pinned");
const hash = (text) => createHash("sha256").update(text).digest("hex");
function source(p) {
	if (cache.has(p)) return cache.get(p);
	const text = readFileSync(resolve(root, p), "utf8"),
		ast = ts.createSourceFile(p, text, ts.ScriptTarget.Latest, true);
	const imports = new Map(),
		variables = new Map(),
		refs = [];
	function visit(n) {
		if (
			ts.isImportDeclaration(n) &&
			n.moduleSpecifier &&
			ts.isStringLiteral(n.moduleSpecifier)
		) {
			refs.push(n.moduleSpecifier.text);
			const bindings = n.importClause?.namedBindings;
			if (bindings && ts.isNamedImports(bindings))
				for (const e of bindings.elements)
					imports.set(e.name.text, {
						path: n.moduleSpecifier.text,
						name: e.propertyName?.text ?? e.name.text,
					});
		} else if (
			ts.isExportDeclaration(n) &&
			n.moduleSpecifier &&
			ts.isStringLiteral(n.moduleSpecifier)
		)
			refs.push(n.moduleSpecifier.text);
		else if (
			ts.isImportTypeNode(n) &&
			ts.isLiteralTypeNode(n.argument) &&
			ts.isStringLiteral(n.argument.literal)
		)
			refs.push(n.argument.literal.text);
		else if (
			ts.isCallExpression(n) &&
			(n.expression.kind === ts.SyntaxKind.ImportKeyword ||
				(ts.isIdentifier(n.expression) && n.expression.text === "require")) &&
			n.arguments[0] &&
			ts.isStringLiteral(n.arguments[0])
		)
			refs.push(n.arguments[0].text);
		if (ts.isVariableDeclaration(n) && ts.isIdentifier(n.name) && n.initializer)
			variables.set(n.name.text, n.initializer);
		ts.forEachChild(n, visit);
	}
	visit(ast);
	const value = { text, ast, imports, variables, refs: [...new Set(refs)] };
	cache.set(p, value);
	return value;
}
function local(p, ref) {
	const q = posix
		.normalize(posix.join(posix.dirname(p), ref))
		.replace(/\.js$/, ".ts");
	for (const x of [q, q + ".ts", q + "/index.ts", q.replace(/\.ts$/, ".json")])
		if (existsSync(resolve(root, x))) return x;
	throw Error(`Unresolved static dependency ${p}: ${ref}`);
}
function unwrap(n) {
	while (
		ts.isAsExpression(n) ||
		ts.isSatisfiesExpression(n) ||
		ts.isParenthesizedExpression(n)
	)
		n = n.expression;
	return n;
}
function literal(p, n) {
	n = unwrap(n);
	if (ts.isIdentifier(n)) {
		const s = source(p),
			i = s.imports.get(n.text);
		if (i)
			return literal(local(p, i.path), ts.factory.createIdentifier(i.name));
		const value = s.variables.get(n.text);
		if (value) return literal(p, value);
	}
	return { p, n };
}
const contracts = [];
function array(p, name, seen = new Set(), factoryKind) {
	const key = p + ":" + name;
	if (seen.has(key)) throw Error("Cyclic contract arrays");
	seen.add(key);
	const s = source(p),
		binding = s.imports.get(name);
	if (binding) {
		array(local(p, binding.path), binding.name, seen, factoryKind);
		seen.delete(key);
		return;
	}
	const n = unwrap(
		s.variables.get(name) ??
			(() => {
				throw Error(`Missing array ${key}`);
			})(),
	);
	if (!ts.isArrayLiteralExpression(n))
		throw Error(`Nonliteral contract array ${key}`);
	for (const element of n.elements) {
		if (ts.isSpreadElement(element) && ts.isIdentifier(element.expression)) {
			array(p, element.expression.text, seen);
			continue;
		}
		if (
			ts.isCallExpression(element) &&
			ts.isIdentifier(element.expression) &&
			source(p).variables.has(element.expression.text)
		) {
			const [nameNode, description, input] = element.arguments;
			const helper = source(p)
				.variables.get(element.expression.text)
				?.getText(source(p).ast);
			const kind = helper?.match(/kind:\s*"([^"]+)"/)?.[1];
			if (
				!kind ||
				!nameNode ||
				!ts.isStringLiteral(nameNode) ||
				!description ||
				!ts.isStringLiteral(description)
			)
				throw Error("Unexpected contract factory");
			contracts.push({
				name: nameNode.text,
				kind,
				description: description.text,
				contract: p,
				line: s.ast.getLineAndCharacterOfPosition(element.getStart()).line + 1,
				inputSchema: input?.getText(s.ast),
				outputSchema: `${element.expression.text} output schema selected by name`,
			});
			continue;
		}
		if (
			ts.isSpreadElement(element) &&
			ts.isCallExpression(element.expression) &&
			ts.isPropertyAccessExpression(element.expression.expression) &&
			element.expression.expression.name.text === "map" &&
			ts.isIdentifier(element.expression.expression.expression)
		) {
			const input = element.expression.expression.expression.text;
			if (
				input !== "HOPPER_MEMORY_TOOL_DEFINITIONS" ||
				!element
					.getText(s.ast)
					.includes("official(name, description, inputSchema)")
			)
				throw Error("Unexpected mapped contracts");
			array(p, input, seen, "official-proxy");
			continue;
		}
		const resolved = literal(p, element),
			object = resolved.n,
			origin = source(resolved.p);
		if (!ts.isObjectLiteralExpression(object))
			throw Error(`Nonliteral contract ${key}: ${element.getText(s.ast)}`);
		const field = (name) =>
			object.properties.find(
				(x) =>
					ts.isPropertyAssignment(x) &&
					(ts.isIdentifier(x.name) || ts.isStringLiteral(x.name)) &&
					x.name.text === name,
			)?.initializer;
		const nameNode = field("name"),
			kind = field("kind"),
			description = field("description");
		if (
			!nameNode ||
			!ts.isStringLiteral(nameNode) ||
			(!kind && !factoryKind) ||
			(kind && !ts.isStringLiteral(kind)) ||
			!description ||
			!ts.isStringLiteral(description)
		)
			throw Error(`Nonliteral contract metadata ${key}`);
		contracts.push({
			name: nameNode.text,
			kind: kind?.text ?? factoryKind,
			description: description.text,
			contract: resolved.p,
			line:
				origin.ast.getLineAndCharacterOfPosition(object.getStart()).line + 1,
			inputSchema: field("inputSchema")?.getText(origin.ast),
			outputSchema: field("outputSchema")?.getText(origin.ast),
		});
	}
	seen.delete(key);
}
array("src/contracts/toolContracts.ts", "TOOL_CONTRACTS");
const effectsModule = await import(
	(await import("node:url")).pathToFileURL(
		resolve(root, "src/contracts/toolEffects.ts"),
	).href
);
const effects = effectsModule.TOOL_EFFECTS;
const names = contracts.map((x) => x.name);
if (
	new Set(names).size !== names.length ||
	JSON.stringify([...names].sort()) !==
		JSON.stringify(Object.keys(effects).sort())
)
	throw Error("Tool registry/effect audit mismatch");
const ports = {
 inspect_electron_fuses: {
  route:"reverse_engineer.javascript_analysis",
  options:{electronFuses:true},
  tests:["sdk/packages/core/src/analysis/electron-fuses.test.ts","sdk/packages/core/src/analysis/semantic-engine/electron-fuses-parity.test.ts"],
  limitation:"Exact pinned streaming parser for one session-confined regular PE/ELF/Mach-O executable. No automatic macOS app-bundle resolution, fuse modification, target execution or Inspector readiness certification. Static inspection remains partial."
 },
	analyze_javascript_application: {
		route: "reverse_engineer.javascript_analysis",
		options: { semanticGraph: true, applicationGraph: true },
		tests: [
			"sdk/packages/core/src/analysis/semantic-engine/application-parity.test.ts",
			"sdk/packages/core/src/analysis/application-evidence.test.ts",
		],
		limitation:
			"Admitted-source virtual inventory; no complete container inventory, source selection or acquisition parity.",
	},
	trace_javascript_semantics: {
		route: "reverse_engineer.analysis_evidence",
		view: "semantic-trace",
		tests: [
			"sdk/packages/core/src/analysis/semantic-engine/parity.test.ts",
			"sdk/packages/core/src/analysis/semantic-evidence.test.ts",
		],
		limitation:
			"Saved file-local semantics; optional application-node bindings, not a whole-program cross-module solver.",
	},
	trace_application_feature: {
		route: "reverse_engineer.analysis_evidence",
		view: "application-trace",
	},
	compare_application_versions: {
		route: "reverse_engineer.analysis_evidence",
		view: "application-comparison",
	},
	compare_javascript_export_shapes: {
		route: "reverse_engineer.analysis_evidence",
		view: "application-exports",
	},
	compare_source_to_bundle: {
		route: "reverse_engineer.analysis_evidence",
		view: "application-source-bundle",
		limitation:
			"Historical input is only the admitted receipt source manifest, with no VCS or complete relationship inventory.",
	},
};
for (const name of Object.keys(ports))
	if (!names.includes(name))
		throw Error("Port map names unknown upstream contract");
function walk(dir) {
	return readdirSync(resolve(root, dir), { withFileTypes: true }).flatMap(
		(e) =>
			e.isDirectory()
				? walk(dir + "/" + e.name)
				: e.isFile() && /\.(test|spec)\.ts$/.test(e.name)
					? [dir + "/" + e.name]
					: [],
	);
}
const mentions = new Map(names.map((n) => [n, []]));
for (const p of [...walk("src"), ...walk("tests")].sort()) {
	const text = readFileSync(resolve(root, p), "utf8");
	for (const n of names)
		if (text.includes('"' + n + '"') || text.includes("'" + n + "'"))
			mentions.get(n).push(p);
}
// A static import graph includes type-only dependencies; it is not a runtime/SBOM claim.
const deps = new Map();
function closure(p) {
	if (deps.has(p)) return;
	deps.set(p, []);
	if (!p.endsWith(".ts")) return;
	const refs = source(p).refs;
	const list = refs.map((ref) =>
		ref.startsWith(".") ? { file: local(p, ref) } : { external: ref },
	);
	deps.set(p, list);
	for (const r of list) if (r.file) closure(r.file);
}
closure("src/contracts/toolContracts.ts");
const files = [...deps.keys()].sort(),
	indexes = new Map(files.map((p, i) => [p, i]));
const inventory = {
	schema: "cline-rea-capability-inventory/1",
	revision: "d0067ba34a39ea47dd7e11bb2e6169bc0938cc3f",
	registry: "src/contracts/toolContracts.ts",
	registrySha256: hash(source("src/contracts/toolContracts.ts").text),
	scope:
		"All public tool contracts in the pinned registry. A name match is not capability parity. Test references are lexical mentions, not proof of coverage. Unmapped means not source-ported/audited here, even if Cline has a separate overlapping feature.",
	tools: contracts.map((c) => ({
		...c,
		upstreamEffects: effects[c.name],
		prerequisites:
			"Provider, host permissions, owned target and format prerequisites remain as described by the upstream contract; no availability or readiness is inferred.",
		dependencyRoot: indexes.get(c.contract),
		upstreamTestReferences: mentions.get(c.name),
		migration: ports[c.name]
			? {
					status: "partial-source-port",
					...ports[c.name],
					tests: ports[c.name].tests ?? [
						"sdk/packages/core/src/analysis/application-evidence.test.ts",
					],
					limitation:
						ports[c.name].limitation ??
						"Saved admitted-source graphs only; no native/runtime Evidence acquisition or full upstream workflow parity.",
				}
			: {
					status: "not-source-ported-or-audited",
					route: null,
					tests: [],
					limitation:
						"No parity claim. Existing overlapping Cline tools require separate source/effect/fixture review.",
				},
	})),
};
const graph = {
	schema: "cline-rea-contract-dependencies/1",
	revision: inventory.revision,
	scope:
		"Static literal TypeScript import/export/import-type/require dependency closure, including types. Not provider scripts, dynamic imports, runtime closure or software inventory.",
	files: files.map((p) => ({
		path: p,
		sha256: hash(readFileSync(resolve(root, p))),
		dependencies: deps
			.get(p)
			.map((r) => (r.file ? { file: indexes.get(r.file) } : r)),
	})),
};
for (const [p, data] of [
	["docs/rea-migration/capabilities.json", inventory],
	["docs/rea-migration/contract-dependencies.json", graph],
]) {
	const text = JSON.stringify(data, null, 2) + "\n",
		out = resolve(repo, p);
	if (process.argv.includes("--check")) {
		if (readFileSync(out, "utf8") !== text)
			throw Error("Inventory drift: " + p);
	} else writeFileSync(out, text);
}
console.log(
	`Pinned capability audit: ${contracts.length} contracts, ${files.length} static dependency files; no full-parity claim.`,
);
