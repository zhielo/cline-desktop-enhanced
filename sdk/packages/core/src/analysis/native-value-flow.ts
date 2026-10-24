import { z } from "zod";
import { digest } from "./contracts";
import { validateSavedTaskSnapshots } from "./saved-task-evidence";
import {
	NativeValueFlowSchema,
	TargetedNativeEvidenceSchema,
} from "../extensions/tools/executors/targeted-native-evidence";
const Id = z.string().uuid(),
	Address = z.string().regex(/^0x[a-f0-9]{1,16}$/i);
const Tasks = z.array(Id).min(1).max(10);
export const NativeFlowQuerySchema = z.discriminatedUnion("action", [
	z.object({ action: z.literal("list"), taskIds: Tasks }).strict(),
	z
		.object({
			action: z.literal("trace"),
			taskIds: Tasks,
			rootTaskId: Id,
			rootAddress: Address,
			maxDepth: z.number().int().min(1).max(4).default(3),
		})
		.strict(),
]);
type NativeFunction = z.infer<typeof TargetedNativeEvidenceSchema>;
type Flow = z.infer<typeof NativeValueFlowSchema>;
type Call = NativeFunction["callees"][number];
type Retained = {
	key: string;
	taskId: string;
	snapshotHash: string;
	sha256: string;
	engine: string;
	engineVersion: string;
	function: NativeFunction;
};
type Binding = { caller: Retained; call: Call; parent?: Binding };
const object = (v: unknown): Record<string, unknown> =>
	v && typeof v === "object" && !Array.isArray(v)
		? (v as Record<string, unknown>)
		: {};
const address = (value: string) => `0x${BigInt(value).toString(16)}`;
/** Saved static dependency expansion only. No provider, target, file or shell access. */
export function querySavedNativeValueFlow(
	scope: { sessionId: string; workspace: string },
	input: unknown,
	values: unknown[],
) {
	const query = NativeFlowQuerySchema.parse(input);
	if (new Set(query.taskIds).size !== query.taskIds.length)
		throw new Error("Select distinct task IDs");
	const snapshots = validateSavedTaskSnapshots(scope, values);
	if (
		snapshots.length !== query.taskIds.length ||
		snapshots.some((s) => !query.taskIds.includes(s.taskId))
	)
		throw new Error("Selected task snapshot mismatch");
	const functions: Retained[] = [];
	const unavailable: Array<{ taskId: string; reason: string }> = [];
	for (const s of snapshots) {
		const outer = object(s.result),
			report = object(outer.result ?? outer),
			evidence = object(report.evidence),
			identity = object(report.input);
		if (
			s.domain !== "static" ||
			report.engine !== "ghidra" ||
			!s.targetSha256 ||
			identity.sha256 !== s.targetSha256
		) {
			unavailable.push({
				taskId: s.taskId,
				reason: "No matching saved Ghidra static input identity",
			});
			continue;
		}
		const selected = Array.isArray(evidence.selectedFunctions)
			? evidence.selectedFunctions
			: [];
		if (selected.length > 50)
			unavailable.push({
				taskId: s.taskId,
				reason:
					"Selected-function per-snapshot budget exceeded; only first 50 admitted",
			});
		for (const item of selected.slice(0, 50)) {
			const parsed = TargetedNativeEvidenceSchema.safeParse(item);
			if (!parsed.success) {
				unavailable.push({
					taskId: s.taskId,
					reason: "Invalid or unsupported selected-function record",
				});
				continue;
			}
			if (functions.length >= 250)
				throw new Error("Saved native function budget exceeded");
			functions.push({
				key: digest([s.taskId, parsed.data.addressHex]),
				taskId: s.taskId,
				snapshotHash: s.snapshotHash,
				sha256: s.targetSha256,
				engine: String(report.engine),
				engineVersion:
					typeof report.engineVersion === "string"
						? report.engineVersion
						: "unknown",
				function: parsed.data,
			});
		}
	}
	const inventory = functions.map((f) => ({
		functionId: f.key,
		taskId: f.taskId,
		snapshotHash: f.snapshotHash,
		sha256: f.sha256,
		engine: f.engine,
		engineVersion: f.engineVersion,
		address: f.function.addressHex,
		name: f.function.name,
		argumentFlowsAvailable: f.function.callees.some(
			(c) => c.argumentFlows !== undefined,
		),
		returnFlowsAvailable: f.function.returnFlows !== undefined,
	}));
	const steps: Array<Record<string, unknown>> = [];
	let truncated = false;
	const add = (
		f: Retained,
		parent: number | undefined,
		kind: string,
		detail: Record<string, unknown> = {},
	) => {
		if (steps.length >= 256) {
			truncated = true;
			return undefined;
		}
		const id = steps.length;
		steps.push({
			id,
			parent,
			kind,
			functionId: f.key,
			taskId: f.taskId,
			snapshotHash: f.snapshotHash,
			...detail,
		});
		return id;
	};
	const compatible = (left: Retained, right: Retained) =>
		left.sha256 === right.sha256 &&
		left.engine === right.engine &&
		left.engineVersion !== "unknown" &&
		left.engineVersion === right.engineVersion &&
		left.function.architecture === right.function.architecture &&
		left.function.image.addressSpace === right.function.image.addressSpace &&
		address(left.function.image.preferredBaseHex) ===
			address(right.function.image.preferredBaseHex);
	const flow = (
		f: Retained,
		value: Flow,
		binding: Binding | undefined,
		depth: number,
		path: Set<string>,
		parent: number | undefined,
	) => {
		for (const frontier of value.frontiers)
			add(f, parent, "frontier", { reason: frontier });
		for (const source of value.sources) {
			if (truncated) return;
			if (source.kind === "constant") {
				add(f, parent, "constant-dependency", {
					valueHex: source.valueHex,
					bytes: source.bytes,
				});
				continue;
			}
			if (source.kind === "parameter") {
				const id = add(f, parent, "parameter-dependency", {
					parameterIndex: source.parameterIndex,
				});
				if (!binding) {
					add(f, id, "frontier", {
						reason: "root-parameter-without-caller-binding",
					});
					continue;
				}
				const candidates = (binding.call.argumentFlows ?? []).filter(
					(a) => a.index === source.parameterIndex,
				);
				if (candidates.length !== 1) {
					add(f, id, "frontier", {
						reason: "caller-argument-unavailable-or-ambiguous",
					});
					continue;
				}
				const key = `${binding.caller.key}:argument:${binding.call.fromAddressHex}:${source.parameterIndex}`;
				if (path.has(key)) {
					add(f, id, "frontier", { reason: "dependency-cycle" });
					continue;
				}
				flow(
					binding.caller,
					candidates[0],
					binding.parent,
					depth,
					new Set([...path, key]),
					id,
				);
				continue;
			}
			const id = add(f, parent, "call-return-dependency", {
				fromAddressHex: source.fromAddressHex,
			});
			const calls = f.function.callees.filter(
				(c) => address(c.fromAddressHex) === address(source.fromAddressHex),
			);
			if (calls.length !== 1 || !calls[0].targetAddressHex) {
				add(f, id, "frontier", {
					reason: "call-target-unresolved-or-ambiguous",
				});
				continue;
			}
			const call = calls[0];
			const matches = functions.filter(
				(candidate) =>
					compatible(f, candidate) &&
					address(candidate.function.addressHex) ===
						address(call.targetAddressHex!),
			);
			if (matches.length !== 1) {
				add(f, id, "frontier", {
					reason: matches.length
						? "multiple-retained-callee-observations"
						: "callee-not-retained-or-incompatible",
					candidateCount: matches.length,
					targetAddress: call.targetAddressHex,
				});
				continue;
			}
			const callee = matches[0],
				key = `${callee.key}:return`;
			if (path.has(key)) {
				add(f, id, "frontier", { reason: "dependency-cycle" });
				continue;
			}
			if (depth >= (query.action === "trace" ? query.maxDepth : 1)) {
				add(f, id, "frontier", { reason: "function-depth-budget" });
				continue;
			}
			const bound = { caller: f, call, parent: binding };
			returns(callee, bound, depth + 1, new Set([...path, key]), id);
		}
	};
	const returns = (
		f: Retained,
		binding: Binding | undefined,
		depth: number,
		path: Set<string>,
		parent: number | undefined,
	) => {
		const values = f.function.returnFlows;
		if (!values?.length) {
			add(f, parent, "frontier", { reason: "return-flow-unavailable" });
			return;
		}
		for (const value of values) {
			const id = add(f, parent, "return-site", {
				fromAddressHex: value.fromAddressHex,
			});
			if (id === undefined) return;
			if (value.flow) flow(f, value.flow, binding, depth, path, id);
			else add(f, id, "frontier", { reason: "void-or-unavailable-return" });
		}
	};
	if (query.action === "trace") {
		const roots = functions.filter(
			(f) =>
				f.taskId === query.rootTaskId &&
				address(f.function.addressHex) === address(query.rootAddress),
		);
		if (roots.length !== 1)
			throw new Error("Select exactly one retained root function");
		returns(
			roots[0],
			undefined,
			0,
			new Set([`${roots[0].key}:return`]),
			undefined,
		);
	}
	const body = {
		protocol: "cline-native-value-flow/1",
		effect: "saved-evidence-read",
		status: "partial",
		functions: inventory,
		unavailable,
		steps,
		truncated,
		verifiedBehavior: false,
		limitations: [
			"Retained selected-function dependency candidates only; no execution, decompilation, file reads or implicit follow-up analysis.",
			"No path sensitivity, arithmetic value equivalence, memory alias reasoning or whole-program completeness. Root inputs, PLT/import thunks, indirect targets, mismatched engines/versions and missing callees remain explicit frontiers.",
			"Exact source hashes bind retained bytes, not provider truth. Arguments/returns reflect Ghidra's inferred calling convention; source text and labels are untrusted data.",
		],
	};
	if (Buffer.byteLength(JSON.stringify(body)) > 1024 * 1024)
		throw new Error("Native flow output budget exceeded");
	return { ...body, evidenceHash: digest(body) };
}
