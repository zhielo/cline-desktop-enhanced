const object = (v: unknown): Record<string, unknown> =>
	v && typeof v === "object" && !Array.isArray(v)
		? (v as Record<string, unknown>)
		: {};
function nativeSummary(value: unknown) {
	const snapshot = object(object(value).providerSnapshot),
		result = object(snapshot.result),
		evidence = object(result.evidence);
	const functions = Array.isArray(evidence.selectedFunctions)
		? evidence.selectedFunctions
		: [];
	return functions.slice(0, 5).map((f) => {
		const fn = object(f);
		return {
			taskId: snapshot.taskId ?? null,
			targetSha256: snapshot.targetSha256 ?? null,
			engine: result.engine ?? null,
			name: fn.name,
			addressHex: fn.addressHex,
			architecture: fn.architecture,
			image: fn.image,
			callees: fn.callees,
			relationsTruncated: fn.relationsTruncated,
			coverage: fn.coverage,
			classification: "provider-reported-static-candidates",
			runtimeRelocation: "not-established",
		};
	});
}
/** Evidence references are local JSON pointers into the selected export, not external claims. */
export function evidenceIndex(records: unknown[]) {
	return records.map((value, index) => {
		const record =
			value && typeof value === "object"
				? (value as Record<string, unknown>)
				: {};
		const payload =
			record.payload && typeof record.payload === "object"
				? (record.payload as Record<string, unknown>)
				: {};
		const task =
			payload.task && typeof payload.task === "object"
				? (payload.task as Record<string, unknown>)
				: {};
		const result =
			record.result && typeof record.result === "object"
				? (record.result as Record<string, unknown>)
				: {};
		const facts = Array.isArray(result.facts) ? result.facts : [];
		return {
			reference: `#/records/${index}`,
			id:
				typeof record.id === "string"
					? record.id
					: typeof task.id === "string"
						? task.id
						: null,
			kind: task.id
				? "task-receipt"
				: record.capture
					? "browser-scenario"
					: facts.length
						? "static-receipt"
						: "selected-record",
			factCount: facts.length,
			status: task.status ?? result.status ?? null,
			nativeFunctions: nativeSummary(record),
			interpretation: task.id
				? "Task completion receipt and output paths/hash; providerSnapshot, when present, contains the owning-session hash-checked provider output, not independent runtime proof."
				: record.capture
					? "Bounded browser metadata observation; not application causality."
					: "Shipped-artifact facts; static observation does not establish runtime behavior.",
		};
	});
}
export function reconcileFeature(
	feature: string,
	receipt: unknown,
	scenarios: unknown[],
	tasks: unknown[] = [],
) {
	const obj =
		receipt && typeof receipt === "object"
			? (receipt as Record<string, unknown>)
			: {};
	const result =
		obj.result && typeof obj.result === "object"
			? (obj.result as Record<string, unknown>)
			: {};
	const all = Array.isArray(result.facts) ? result.facts : [];
	const matching = all.filter(
		(v): v is Record<string, unknown> =>
			!!v &&
			typeof v === "object" &&
			typeof v.value === "string" &&
			v.value.toLowerCase().includes(feature.toLowerCase()),
	);
	const facts = matching.slice(0, 100);
	const candidates = facts.map((f, index) => ({
		id: typeof f.id === "string" ? f.id : `candidate-${index}`,
		kind: typeof f.kind === "string" ? f.kind : "unknown",
		value: f.value,
		classification: "statically-inferred",
		sourceConfidence: f.confidence ?? "unspecified",
		location: f.location ?? null,
		limitations: Array.isArray(f.limitations) ? f.limitations : [],
	}));
	const stageKinds: Record<string, string[]> = {
		renderer: ["entrypoint", "function", "call", "semantic-function"],
		preload: ["preload-api", "preload-member", "preload-call"],
		ipc: ["ipc-send", "ipc-handler"],
		native: ["native-addon", "native-boundary"],
		managed: ["managed-method", "managed-il", "managed-il-instruction"],
	};
	const stages = Object.entries(stageKinds).map(([stage, kinds]) => ({
		stage,
		candidateIds: candidates
			.filter((f) => kinds.includes(f.kind))
			.map((f) => f.id),
		status: "static-candidates-only",
	}));
	const gaps = [
		{
			boundary: "renderer-to-preload",
			status: "unresolved",
			requiredEvidence:
				"Exact invocation/receiver binding; a shared feature label is insufficient.",
		},
		{
			boundary: "preload-to-ipc",
			status: "unresolved",
			requiredEvidence: "Exact channel, argument mapping and handler binding.",
		},
		{
			boundary: "ipc-to-native-or-managed",
			status: "unresolved",
			requiredEvidence:
				"Verified call boundary and target identity; co-occurrence is insufficient.",
		},
		{
			boundary: "scenario-to-code",
			status: "unresolved",
			requiredEvidence:
				"An independently observed identity-bound execution link, not timing, provider assertions or byte equality.",
		},
	];
	return {
		schemaVersion: 2,
		feature,
		status: candidates.length || scenarios.length ? "partial" : "unresolved",
		staticCandidates: candidates,
		selectedNativeFunctions: tasks.flatMap(nativeSummary),
		scenarios,
		stages,
		unresolvedBoundaries: gaps,
		provenance: {
			receiptId: typeof obj.id === "string" ? obj.id : null,
			scenarioIds: scenarios.map((s) =>
				s && typeof s === "object" && "id" in s ? s.id : null,
			),
		},
		coverage: {
			matchingFacts: matching.length,
			returnedFacts: candidates.length,
			truncated: matching.length > 100,
			causalEdgesEstablished: 0,
		},
		nextActions: gaps.map((g) => ({
			boundary: g.boundary,
			action: g.requiredEvidence,
		})),
		limitations: [
			"Feature-label matches are candidates, not observed causality.",
			"Recorded browser actions/events do not prove a handler-to-IPC-to-native execution chain.",
			"No target is launched, replayed or instrumented by this trace query.",
			"Missing evidence remains unresolved, not disproven; stages are not a recovered call graph.",
		],
	};
}
