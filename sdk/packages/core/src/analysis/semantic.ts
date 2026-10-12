import ts from "typescript";
import { LIMITS, type AnalysisFact, type AnalysisResult } from "./contracts";
import type { SourceArtifact } from "./parser";

type Value = string | number | boolean | null;
type Emit = (
	node: ts.Node,
	kind: AnalysisFact["kind"],
	value: string,
	notes: string[],
) => AnalysisFact | undefined;
/** A closed, data-only expression reducer. No target imports or function execution. */
export function analyzeLocalSemantics(
	file: ts.SourceFile,
	source: SourceArtifact,
	emit: Emit,
	edgeBudget: number,
) {
	const options: ts.CompilerOptions = {
		allowJs: true,
		noLib: true,
		noResolve: true,
		target: ts.ScriptTarget.Latest,
	};
	const host: ts.CompilerHost = {
		getSourceFile: (name) => (name === file.fileName ? file : undefined),
		getDefaultLibFileName: () => "",
		writeFile: () => {},
		getCurrentDirectory: () => "",
		getDirectories: () => [],
		fileExists: (name) => name === file.fileName,
		readFile: (name) => (name === file.fileName ? source.source : undefined),
		getCanonicalFileName: (name) => name,
		useCaseSensitiveFileNames: () => true,
		getNewLine: () => "\n",
	};
	const checker = ts
		.createProgram([file.fileName], options, host)
		.getTypeChecker();
	const invalid = new Set<ts.Symbol>(),
		declarations = new Map<ts.Symbol, ts.VariableDeclaration>();
	const functions = new Map<
		ts.Symbol,
		ts.FunctionDeclaration | ts.ArrowFunction | ts.FunctionExpression
	>();
	const functionNames = new Map<ts.Symbol, string>();
	let visits = 0,
		exhausted = false;
	const count = () => {
		if (++visits > LIMITS.nodes) {
			exhausted = true;
			return false;
		}
		return true;
	};
	const symbol = (n: ts.Node) => checker.getSymbolAtLocation(n);
	const walk = (n: ts.Node, fn: (n: ts.Node) => void) => {
		if (!count()) return;
		fn(n);
		ts.forEachChild(n, (c) => walk(c, fn));
	};
	const binding = (n: ts.Expression): ts.Symbol | undefined => {
		if (ts.isIdentifier(n)) return symbol(n);
		if (ts.isPropertyAccessExpression(n) || ts.isElementAccessExpression(n))
			return binding(n.expression);
		return undefined;
	};
	walk(file, (n) => {
		if (
			ts.isVariableDeclaration(n) &&
			ts.isIdentifier(n.name) &&
			ts.isVariableDeclarationList(n.parent) &&
			n.parent.flags & ts.NodeFlags.Const
		) {
			const s = symbol(n.name);
			if (s) {
				declarations.set(s, n);
				if (
					n.initializer &&
					(ts.isArrowFunction(n.initializer) ||
						ts.isFunctionExpression(n.initializer))
				) {
					functions.set(s, n.initializer);
					functionNames.set(s, n.name.text);
				}
			}
		}
		if (ts.isFunctionDeclaration(n) && n.name) {
			const s = symbol(n.name);
			if (s) {
				functions.set(s, n);
				functionNames.set(s, n.name.text);
			}
		}
		if (
			ts.isBinaryExpression(n) &&
			n.operatorToken.kind >= ts.SyntaxKind.FirstAssignment &&
			n.operatorToken.kind <= ts.SyntaxKind.LastAssignment
		) {
			const s = binding(n.left);
			if (s) invalid.add(s);
		}
		if (
			(ts.isPrefixUnaryExpression(n) || ts.isPostfixUnaryExpression(n)) &&
			[ts.SyntaxKind.PlusPlusToken, ts.SyntaxKind.MinusMinusToken].includes(
				n.operator,
			)
		) {
			const s = binding(n.operand);
			if (s) invalid.add(s);
		}
	});
	const notes = [
		"Bounded local static reduction only; not observed execution, complete data flow or behavioral proof.",
	];
	const facts = new Map<ts.Symbol, AnalysisFact>(),
		functionFacts = new Map<ts.Symbol, AnalysisFact>();
	const refs = new Set<ts.Symbol>();
	const reduced = (
		n: ts.Expression | undefined,
		env = new Map<ts.Symbol, Value>(),
		stack = new Set<ts.Symbol>(),
		depth = 0,
	): Value | undefined => {
		if (!n || depth > 16 || !count()) return undefined;
		const next = (e: ts.Expression | undefined) =>
			reduced(e, env, stack, depth + 1);
		if (ts.isStringLiteral(n) || ts.isNoSubstitutionTemplateLiteral(n))
			return n.text.length <= 1000 ? n.text : undefined;
		if (ts.isNumericLiteral(n)) {
			const v = Number(n.text);
			return Number.isFinite(v) ? v : undefined;
		}
		if (n.kind === ts.SyntaxKind.TrueKeyword) return true;
		if (n.kind === ts.SyntaxKind.FalseKeyword) return false;
		if (n.kind === ts.SyntaxKind.NullKeyword) return null;
		if (
			ts.isParenthesizedExpression(n) ||
			ts.isAsExpression(n) ||
			ts.isTypeAssertionExpression(n) ||
			ts.isNonNullExpression(n)
		)
			return next(n.expression);
		if (ts.isIdentifier(n)) {
			const s = symbol(n);
			if (!s || invalid.has(s)) return undefined;
			if (env.has(s)) return env.get(s);
			const d = declarations.get(s);
			if (!d || stack.has(s)) return undefined;
			refs.add(s);
			const chain = new Set(stack);
			chain.add(s);
			return reduced(d.initializer, env, chain, depth + 1);
		}
		if (
			ts.isBinaryExpression(n) &&
			n.operatorToken.kind === ts.SyntaxKind.PlusToken
		) {
			const a = next(n.left),
				b = next(n.right);
			if (a === undefined || b === undefined) return undefined;
			if (typeof a === "string" || typeof b === "string") {
				const v = String(a) + String(b);
				return v.length <= 1000 ? v : undefined;
			}
			if (
				typeof a === "number" &&
				typeof b === "number" &&
				Number.isFinite(a + b)
			)
				return a + b;
			return undefined;
		}
		if (ts.isTemplateExpression(n)) {
			let v = n.head.text;
			for (const span of n.templateSpans) {
				const part = next(span.expression);
				if (part === undefined) return undefined;
				v += String(part) + span.literal.text;
				if (v.length > 1000) return undefined;
			}
			return v;
		}
		if (
			ts.isCallExpression(n) &&
			ts.isIdentifier(n.expression) &&
			n.arguments.length <= 8
		) {
			const s = symbol(n.expression),
				f = s && !invalid.has(s) && functions.get(s);
			if (
				!s ||
				!f ||
				stack.has(s) ||
				!f.body ||
				(ts.isBlock(f.body) &&
					(f.body.statements.length !== 1 ||
						!ts.isReturnStatement(f.body.statements[0]))) ||
				f.parameters.length !== n.arguments.length ||
				("asteriskToken" in f && f.asteriskToken) ||
				f.modifiers?.some((m) => m.kind === ts.SyntaxKind.AsyncKeyword)
			)
				return undefined;
			const params = new Map(env);
			for (let i = 0; i < f.parameters.length; i++) {
				const p = f.parameters[i];
				if (!ts.isIdentifier(p.name) || p.initializer || p.dotDotDotToken)
					return undefined;
				const arg = next(n.arguments[i]),
					ps = symbol(p.name);
				if (arg === undefined || !ps) return undefined;
				params.set(ps, arg);
			}
			const chain = new Set(stack);
			chain.add(s);
			const returned = ts.isBlock(f.body)
				? (f.body.statements[0] as ts.ReturnStatement).expression
				: f.body;
			return reduced(returned, params, chain, depth + 1);
		}
		return undefined;
	};
	for (const [s, d] of declarations) {
		refs.clear();
		const v = reduced(d.initializer);
		if (v === undefined || invalid.has(s)) continue;
		const f = emit(
			d,
			"configuration",
			`${d.name.getText(file)} = ${JSON.stringify(v)}`,
			notes,
		);
		if (f) facts.set(s, f);
	}
	for (const [s, f] of functions) {
		const fact = emit(f, "semantic-function", functionNames.get(s)!, [
			...notes,
			"Lexically bound local function; invocation and reachability unverified.",
		]);
		if (fact) functionFacts.set(s, fact);
	}
	const edges: AnalysisResult["edges"] = [];
	const edge = (
		a: AnalysisFact | undefined,
		b: AnalysisFact | undefined,
		kind: "data-flow" | "calls",
	) => {
		if (a && b && edges.length < edgeBudget)
			edges.push({
				source: a.id,
				target: b.id,
				kind,
				confidence: "derived",
				limitations: notes,
			});
	};
	walk(file, (n) => {
		if (!ts.isCallExpression(n)) return;
		if (ts.isIdentifier(n.expression)) {
			const s = symbol(n.expression),
				f = s && !invalid.has(s) && functionFacts.get(s);
			if (f) {
				const call = emit(n, "resolved-call", n.expression.text, [
					...notes,
					"Symbol resolution, not proof that the call executes.",
				]);
				edge(call, f, "calls");
			}
			if (n.expression.text === "fetch" && !s) {
				refs.clear();
				const url = reduced(n.arguments[0]);
				if (typeof url !== "string") return;
				const request = emit(n, "resolved-endpoint", url, [
					...notes,
					"Unshadowed global-fetch candidate; no request was sent.",
				]);
				for (const r of refs) edge(facts.get(r), request, "data-flow");
			}
		}
	});
	return { edges, visits, exhausted };
}
