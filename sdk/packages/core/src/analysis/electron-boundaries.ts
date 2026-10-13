import ts from "typescript";
import path from "node:path";
import type { ClosedModuleContext } from "./module-context";
export type BoundaryFinding = {
	file: ts.SourceFile;
	node: ts.Node;
	kind:
		| "preload-member"
		| "preload-unresolved"
		| "preload-call"
		| "native-boundary";
	value: string;
};
/** Closed inventory, lexical binding and literal shape candidates only. No Electron/native code runs. */
export function inspectElectronBoundaries(
	context: ClosedModuleContext,
	budget = 50000,
) {
	const findings: BoundaryFinding[] = [],
		links: Array<{
			source: number;
			target: number;
			kind: "preload-candidate" | "native-boundary-candidate";
		}> = [],
		notes: string[] = [],
		windowWrites = new Set<string>();
	const checker = context.checker,
		bindings = new Map<
			ts.Symbol,
			{ role: string; module?: string; export?: string }
		>(),
		invalid = new Set<ts.Symbol>();
	const invalidModules = new Set<string>(),
		dirtyRequireFiles = new Set<string>(),
		commonJSBindings = new Map<string, Set<ts.Symbol>>();
	let visits = 0,
		exhausted = false;
	const files = context.files.filter(
		(f) =>
			!(f as ts.SourceFile & { parseDiagnostics?: ts.Diagnostic[] })
				.parseDiagnostics?.length,
	);
	const literal = (n?: ts.Node) =>
		n && (ts.isStringLiteral(n) || ts.isNoSubstitutionTemplateLiteral(n))
			? n.text
			: undefined;
	const symbol = (n: ts.Node) => checker.getSymbolAtLocation(n);
	const split = (
		n: ts.Expression,
		depth = 0,
	): { root: ts.Identifier; parts: string[] } | undefined => {
		if (depth > 6) return undefined;
		if (
			ts.isParenthesizedExpression(n) ||
			ts.isAsExpression(n) ||
			ts.isTypeAssertionExpression(n) ||
			ts.isNonNullExpression(n) ||
			ts.isSatisfiesExpression(n)
		)
			return split(n.expression, depth + 1);
		if (ts.isIdentifier(n)) return { root: n, parts: [] };
		if (ts.isPropertyAccessExpression(n) && !n.questionDotToken) {
			const p = split(n.expression, depth + 1);
			return p ? { root: p.root, parts: [...p.parts, n.name.text] } : undefined;
		}
		if (ts.isElementAccessExpression(n) && !n.questionDotToken) {
			const name = literal(n.argumentExpression),
				p = split(n.expression, depth + 1);
			return name !== undefined && p
				? { root: p.root, parts: [...p.parts, name] }
				: undefined;
		}
		return undefined;
	};
	const root = (expr: ts.Expression) => {
		let n = expr,
			count = 0;
		while (
			ts.isPropertyAccessExpression(n) ||
			ts.isElementAccessExpression(n) ||
			ts.isParenthesizedExpression(n) ||
			ts.isAsExpression(n) ||
			ts.isTypeAssertionExpression(n) ||
			ts.isNonNullExpression(n) ||
			ts.isSatisfiesExpression(n)
		) {
			if (++count > 32) return undefined;
			n = n.expression;
		}
		return ts.isIdentifier(n) ? n : undefined;
	};
	const escapes = (n: ts.Identifier, allowExposure = false) => {
		const p = n.parent;
		if (ts.isTypeNode(p)) return false;
		if (
			(ts.isVariableDeclaration(p) ||
				ts.isBindingElement(p) ||
				ts.isImportSpecifier(p) ||
				ts.isNamespaceImport(p) ||
				ts.isImportClause(p)) &&
			p.name === n
		)
			return false;
		if (
			(ts.isPropertyAccessExpression(p) || ts.isElementAccessExpression(p)) &&
			p.expression === n
		)
			return false;
		if (ts.isCallExpression(p) && p.expression === n) return false;
		if (
			allowExposure &&
			ts.isCallExpression(p) &&
			exposure(p) &&
			p.arguments[1] === n
		)
			return false;
		return true;
	};
	const register = (
		name: ts.Identifier,
		role: string,
		module?: string,
		exportName?: string,
	) => {
		const s = symbol(name);
		if (s?.declarations?.length === 1)
			bindings.set(s, { role, module, export: exportName });
	};
	const registerCommonJS = (
		name: ts.Identifier,
		role: string,
		module: string,
	) => {
		register(name, role, module);
		const s = symbol(name);
		if (!s || !bindings.has(s)) return;
		const file = name.getSourceFile().fileName,
			items = commonJSBindings.get(file) ?? new Set<ts.Symbol>();
		items.add(s);
		commonJSBindings.set(file, items);
	};
	for (const file of files)
		for (const statement of file.statements) {
			if (
				ts.isImportDeclaration(statement) &&
				!statement.importClause?.isTypeOnly
			) {
				const label = literal(statement.moduleSpecifier),
					b = statement.importClause?.namedBindings;
				if (label !== "electron" && !label?.endsWith(".node")) continue;
				if (b && ts.isNamespaceImport(b))
					register(b.name, label === "electron" ? "electron" : "native", label);
				if (b && ts.isNamedImports(b))
					for (const e of b.elements)
						if (!e.isTypeOnly) {
							const name = e.propertyName?.text ?? e.name.text;
							register(
								e.name,
								label === "electron" ? name : "native",
								label,
								label === "electron" ? undefined : name,
							);
						}
				if (label?.endsWith(".node") && statement.importClause?.name)
					register(statement.importClause.name, "native", label);
			}
			if (
				ts.isVariableStatement(statement) &&
				statement.declarationList.flags & ts.NodeFlags.Const
			)
				for (const d of statement.declarationList.declarations) {
					const n = d.initializer;
					if (
						!n ||
						!ts.isCallExpression(n) ||
						n.arguments.length !== 1 ||
						!ts.isIdentifier(n.expression) ||
						n.expression.text !== "require" ||
						symbol(n.expression)?.declarations?.length
					)
						continue;
					const label = literal(n.arguments[0]);
					if (label !== "electron" && !label?.endsWith(".node")) continue;
					if (ts.isIdentifier(d.name))
						registerCommonJS(
							d.name,
							label === "electron" ? "electron" : "native",
							label,
						);
					if (label === "electron" && ts.isObjectBindingPattern(d.name))
						for (const b of d.name.elements)
							if (
								ts.isIdentifier(b.name) &&
								!b.dotDotDotToken &&
								!b.initializer
							) {
								const name =
									b.propertyName && ts.isIdentifier(b.propertyName)
										? b.propertyName.text
										: b.name.text;
								registerCommonJS(b.name, name, label);
							}
				}
		}
	const walk = (node: ts.Node, fn: (n: ts.Node) => void) => {
		if (exhausted) return;
		if (++visits > budget) {
			exhausted = true;
			return;
		}
		fn(node);
		ts.forEachChild(node, (n) => walk(n, fn));
	};
	const moduleKey = (symbol: ts.Symbol) => {
		const b = bindings.get(symbol);
		if (!b?.module) return undefined;
		const file = symbol.declarations?.[0]?.getSourceFile().fileName;
		return b.module.startsWith(".") && file
			? path.posix.normalize(
					path.posix.join(path.posix.dirname(file), b.module),
				)
			: b.module;
	};
	const invalidate = (symbol: ts.Symbol) => {
		invalid.add(symbol);
		const key = moduleKey(symbol);
		if (key) invalidModules.add(key);
	};
	// Scan every included file before deriving bindings: explicit writes, deletes, updates and escapes invalidate identities.
	for (const file of files)
		walk(file, (n) => {
			let target: ts.Expression | undefined;
			if (
				ts.isBinaryExpression(n) &&
				n.operatorToken.kind >= ts.SyntaxKind.FirstAssignment &&
				n.operatorToken.kind <= ts.SyntaxKind.LastAssignment
			)
				target = n.left;
			if (ts.isDeleteExpression(n)) target = n.expression;
			if (
				(ts.isPrefixUnaryExpression(n) || ts.isPostfixUnaryExpression(n)) &&
				[ts.SyntaxKind.PlusPlusToken, ts.SyntaxKind.MinusMinusToken].includes(
					n.operator,
				)
			)
				target = n.operand;
			const r = target && root(target),
				s = r && symbol(r);
			if (s) invalidate(s);
			if (r?.text === "require" && !s?.declarations?.length)
				dirtyRequireFiles.add(file.fileName);
			if (r?.text === "window" && !s) {
				const p = target && split(target);
				windowWrites.add(p?.parts[0] ?? "*");
			}
			if (ts.isIdentifier(n)) {
				const s = symbol(n);
				if (s && bindings.has(s) && escapes(n)) invalidate(s);
				if (n.text === "require" && !s?.declarations?.length && escapes(n))
					dirtyRequireFiles.add(file.fileName);
			}
		});
	if (exhausted)
		return {
			findings: [],
			links: [],
			electronBindingsExcluded: true,
			visits,
			notes: [
				"Boundary mutation scan budget reached; no binding relationships inferred.",
			],
		};
	for (const file of dirtyRequireFiles)
		for (const s of commonJSBindings.get(file) ?? []) invalidate(s);
	if (invalidModules.size)
		notes.push(
			"Mutated/escaped literal module identities excluded across inventory; runtime load identity is not established.",
		);
	const bound = (expr: ts.Expression) => {
		const p = split(expr),
			s = p && symbol(p.root),
			b = s && bindings.get(s);
		if (
			!p ||
			!s ||
			!b ||
			invalid.has(s) ||
			invalidModules.has(moduleKey(s) ?? "")
		)
			return undefined;
		return {
			role: b.role === "electron" ? p.parts[0] : b.role,
			parts: b.role === "electron" ? p.parts.slice(1) : p.parts,
			module: b.module,
			export: b.export,
		};
	};
	const emit = (
		file: ts.SourceFile,
		node: ts.Node,
		kind: BoundaryFinding["kind"],
		value: unknown,
	) => {
		if (findings.length >= 256) {
			notes.push("Boundary finding budget reached");
			return undefined;
		}
		const text = JSON.stringify(value);
		if (text.length > 900) {
			notes.push("Boundary value budget reached; record omitted");
			return undefined;
		}
		findings.push({ file, node, kind, value: text });
		return findings.length - 1;
	};
	const exposure = (n: ts.CallExpression) => {
		const b = bound(n.expression);
		return (
			b?.role === "contextBridge" &&
			b.parts.join(".") === "exposeInMainWorld" &&
			n.arguments.length === 2
		);
	};
	const objectEscapes = new Set<ts.Symbol>();
	for (const file of files)
		walk(file, (n) => {
			if (!ts.isIdentifier(n)) return;
			const s = symbol(n);
			if (s && escapes(n, true)) objectEscapes.add(s);
		});
	if (exhausted)
		return {
			findings: [],
			links: [],
			electronBindingsExcluded: true,
			visits,
			notes: [
				"Boundary escape scan budget reached; no object relationships inferred.",
			],
		};
	const object = (
		n: ts.Expression,
		seen = new Set<ts.Symbol>(),
	): ts.ObjectLiteralExpression | undefined => {
		if (ts.isObjectLiteralExpression(n)) return n;
		if (!ts.isIdentifier(n)) return undefined;
		const s = symbol(n);
		if (
			!s ||
			invalid.has(s) ||
			objectEscapes.has(s) ||
			seen.has(s) ||
			seen.size > 4
		)
			return undefined;
		seen.add(s);
		const ds = s.declarations;
		if (
			ds?.length !== 1 ||
			!ts.isVariableDeclaration(ds[0]) ||
			!(ds[0].parent.flags & ts.NodeFlags.Const) ||
			!ds[0].initializer ||
			ds[0].getSourceFile() !== n.getSourceFile()
		)
			return undefined;
		return object(ds[0].initializer, seen);
	};
	const functionShape = (
		expr: ts.Expression,
		seen = new Set<ts.Symbol>(),
	):
		| ts.ArrowFunction
		| ts.FunctionExpression
		| ts.FunctionDeclaration
		| undefined => {
		if (ts.isArrowFunction(expr) || ts.isFunctionExpression(expr)) return expr;
		if (!ts.isIdentifier(expr)) return undefined;
		const s = ts.isShorthandPropertyAssignment(expr.parent)
			? checker.getShorthandAssignmentValueSymbol(expr.parent)
			: symbol(expr);
		if (
			!s ||
			invalid.has(s) ||
			seen.has(s) ||
			seen.size >= 4 ||
			s.declarations?.length !== 1
		)
			return undefined;
		seen.add(s);
		const d = s.declarations[0];
		if (ts.isFunctionDeclaration(d) && d.body) return d;
		if (
			ts.isVariableDeclaration(d) &&
			d.parent.flags & ts.NodeFlags.Const &&
			d.initializer
		)
			return functionShape(d.initializer, seen);
		return undefined;
	};
	const nativeCalls = new Map<ts.CallExpression, number>(),
		nativeLinks: Array<{ member: number; call: ts.CallExpression }> = [];
	const apiNames = new Set<string>();
	const members: Array<{
		api: string;
		path: string[];
		index: number;
		callable: boolean;
	}> = [];
	for (const file of files)
		walk(file, (n) => {
			if (!ts.isCallExpression(n) || n.questionDotToken) return;
			const b = bound(n.expression);
			if (b?.role === "native") {
				const index = emit(file, n, "native-boundary", {
					module: b.module,
					exportPath: [...(b.export ? [b.export] : []), ...b.parts],
					argumentCount: n.arguments.length,
					scope: "lexical-call-candidate-native-export-unverified",
				});
				if (index !== undefined) nativeCalls.set(n, index);
			}
			if (!exposure(n)) return;
			const api = literal(n.arguments[0]);
			if (!api || api.length > 120) return;
			apiNames.add(api);
			const inspect = (expr: ts.Expression, path: string[], depth: number) => {
				const o = object(expr);
				if (!o || depth > 4 || o.properties.length > 32) {
					emit(file, n, "preload-unresolved", {
						api,
						path,
						reason: "Unsupported/mutable/escaped object or shape budget",
					});
					return;
				}
				const keys: string[] = [],
					props: Array<
						| ts.PropertyAssignment
						| ts.MethodDeclaration
						| ts.ShorthandPropertyAssignment
					> = [];
				for (const p of o.properties) {
					if (
						!ts.isPropertyAssignment(p) &&
						!ts.isMethodDeclaration(p) &&
						!ts.isShorthandPropertyAssignment(p)
					) {
						emit(file, n, "preload-unresolved", {
							api,
							path,
							reason: "Getter, spread or unsupported property shape",
						});
						return;
					}
					const name = ts.isIdentifier(p.name) ? p.name.text : literal(p.name);
					if (
						!name ||
						name.length > 60 ||
						keys.includes(name) ||
						name === "__proto__"
					) {
						emit(file, n, "preload-unresolved", {
							api,
							path,
							reason: "Computed/duplicate/unbounded member name",
						});
						return;
					}
					keys.push(name);
					props.push(p);
				}
				for (let i = 0; i < props.length; i++) {
					const p = props[i],
						key = [...path, keys[i]],
						value = ts.isPropertyAssignment(p)
							? p.initializer
							: ts.isShorthandPropertyAssignment(p) &&
									!p.objectAssignmentInitializer
								? p.name
								: undefined;
					if (value && object(value)) {
						inspect(value, key, depth + 1);
						continue;
					}
					const fn = ts.isMethodDeclaration(p)
						? p
						: value
							? functionShape(value)
							: undefined;
					const body = fn?.body,
						call =
							body && ts.isBlock(body)
								? body.statements.length === 1 &&
									ts.isReturnStatement(body.statements[0])
									? body.statements[0].expression
									: undefined
								: body;
					const unwrappedCall =
						call && ts.isAwaitExpression(call) ? call.expression : call;
					const ipc =
							unwrappedCall && ts.isCallExpression(unwrappedCall)
								? bound(unwrappedCall.expression)
								: undefined,
						channel =
							unwrappedCall && ts.isCallExpression(unwrappedCall)
								? literal(unwrappedCall.arguments[0])
								: undefined;
					const index = emit(file, p, "preload-member", {
						api,
						path: key,
						callable: fn
							? true
							: value &&
									[
										ts.SyntaxKind.NumericLiteral,
										ts.SyntaxKind.StringLiteral,
										ts.SyntaxKind.TrueKeyword,
										ts.SyntaxKind.FalseKeyword,
										ts.SyntaxKind.NullKeyword,
									].includes(value.kind)
								? false
								: "unknown",
						...(ipc?.role === "ipcRenderer" &&
						["invoke", "send", "sendSync"].includes(ipc.parts.join(".")) &&
						channel !== undefined
							? { ipcMethod: ipc.parts.join("."), channel }
							: {}),
						...(ipc?.role === "native"
							? {
									nativeModule: ipc.module,
									nativeExportPath: [
										...(ipc.export ? [ipc.export] : []),
										...ipc.parts,
									],
								}
							: {}),
						scope: "static-exposure-shape-not-runtime-binding",
					});
					if (index !== undefined) {
						members.push({ api, path: key, index, callable: !!fn });
						if (
							ipc?.role === "native" &&
							unwrappedCall &&
							ts.isCallExpression(unwrappedCall)
						)
							nativeLinks.push({ member: index, call: unwrappedCall });
					}
				}
			};
			inspect(n.arguments[1], [], 0);
		});
	for (const file of files)
		walk(file, (n) => {
			if (!ts.isCallExpression(n) || n.questionDotToken) return;
			const p = split(n.expression);
			if (
				!p ||
				p.root.text !== "window" ||
				symbol(p.root) ||
				p.parts.length < 2 ||
				!apiNames.has(p.parts[0]) ||
				windowWrites.has("*") ||
				windowWrites.has(p.parts[0])
			)
				return;
			const matches = members.filter(
				(m) =>
					m.callable &&
					m.api === p.parts[0] &&
					JSON.stringify(m.path) === JSON.stringify(p.parts.slice(1)),
			);
			const index = emit(file, n, "preload-call", {
				api: p.parts[0],
				path: p.parts.slice(1),
				matchingExposures: matches.length,
				scope:
					matches.length === 1
						? "unique-static-shape-candidate"
						: "unresolved-or-ambiguous-exposure",
			});
			if (index !== undefined && matches.length === 1)
				links.push({
					source: index,
					target: matches[0].index,
					kind: "preload-candidate",
				});
		});
	for (const link of nativeLinks) {
		const target = nativeCalls.get(link.call);
		if (target !== undefined)
			links.push({
				source: link.member,
				target,
				kind: "native-boundary-candidate",
			});
	}
	if (exhausted)
		notes.push("Boundary AST budget reached; remaining syntax uninspected");
	return {
		findings,
		links,
		visits,
		notes: [...new Set(notes)],
		electronBindingsExcluded: invalidModules.has("electron"),
	};
}
