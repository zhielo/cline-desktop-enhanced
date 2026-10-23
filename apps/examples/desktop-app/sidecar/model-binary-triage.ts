import { randomUUID } from "node:crypto";
import { BinaryTriageCallSchema } from "@cline/core";
import type {
	AnalysisWorkflowStore,
	WorkflowScope,
} from "./analysis-workflow-store";
import { BinaryTriageService, triageEvidencePage } from "./binary-triage";

export interface ModelTriagePorts {
	service: BinaryTriageService;
	store: AnalysisWorkflowStore;
	scope: WorkflowScope;
	signal?: AbortSignal;
	assertCurrent(execution: boolean): void;
	review(details: Record<string, unknown>): Promise<boolean>;
}
/** A host-only closure owns approval and execution. No token/confirmation is accepted from the model. */
export async function runModelBinaryTriage(
	raw: unknown,
	ports: ModelTriagePorts,
): Promise<string> {
	const call = BinaryTriageCallSchema.parse(raw),
		options = call.advanced_options.binary_triage;
	const current = () => {
		ports.signal?.throwIfAborted();
		ports.assertCurrent(options.action === "run");
	};
	current();
	if (options.action === "status")
		return JSON.stringify(await ports.service.status());
	if (options.action === "read")
		return JSON.stringify(
			triageEvidencePage(
				ports.store.get(ports.scope, options.receipt_id, "triage"),
				options.offset,
				options.limit,
			),
		);
	const { action: _, ...selection } = options;
	const input = { ...selection, target: call.target };
	const approval = await ports.service.prepare(ports.scope, input);
	current();
	if (
		!(await ports.review({
			category: "binary_triage",
			independentStaticAnalysisApproval: true,
			...approval,
			constraints:
				"Static only; no target launch, arbitrary commands, custom rules or FLOSS decoding",
		}))
	)
		throw new Error("Static triage approval denied or unavailable");
	current();
	const record = await ports.service.run(
		ports.scope,
		input,
		ports.store,
		randomUUID(),
		{
			expected: approval,
			signal: ports.signal,
			assertCurrent: () => ports.assertCurrent(true),
		},
	);
	return JSON.stringify(triageEvidencePage(record));
}
