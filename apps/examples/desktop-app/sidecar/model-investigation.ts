import { InvestigationSchemas, type InvestigationToolName } from "@cline/core";
import { sanitizeEvidence } from "./analysis-workflow";
export interface ModelInvestigationPorts {
	invoke(command: string, input: Record<string, unknown>): Promise<unknown>;
	review(details: Record<string, unknown>): Promise<boolean>;
	approve(plan: { id: string; requestHash: string; requirements: string[] }): {
		executionToken: string;
	};
	cancel(planId: string): void;
	assertCurrent(): void;
	signal?: AbortSignal;
	mode?: string;
}
/** Host-only transaction. The model never handles the approval token. */
export async function runModelInvestigation(
	name: InvestigationToolName,
	raw: unknown,
	ports: ModelInvestigationPorts,
): Promise<string> {
	const input = InvestigationSchemas[name].parse(raw);
	const current = () => {
		ports.signal?.throwIfAborted();
		ports.assertCurrent();
	};
	current();
	if (name === "capture_browser_scenario") {
		const req = input as { action: string };
		if (req.action === "list") {
			const status = (await ports.invoke("analysis_workflow_status", {})) as {
				browsers: unknown;
				mode?: string;
			};
			return JSON.stringify(
				sanitizeEvidence({
					browsers: status.browsers,
					mode: status.mode,
					...(status.mode === "hybrid"
						? {
								workflow:
									"Inspect first; name an unresolved question and static receipt/task basis before requesting human recording consent. No automatic execution.",
							}
						: {}),
				}),
			);
		}
		// Stopping existing observation is cleanup, not authorization to start it.
		if (req.action === "start") {
			const hybrid =
				ports.mode === "hybrid"
					? await ports.invoke(
							"analysis_workflow_hybrid_prepare",
							(input as { hybridProposal?: Record<string, unknown> })
								.hybridProposal ?? {},
						)
					: undefined;
			current();
			if (
				!(await ports.review({
					operation: name,
					...input,
					scope: "owned-built-in-browser-metadata-only",
					independentRecordingConsent: true,
					...(hybrid ? { hybrid } : {}),
				}))
			)
				throw new Error("Recording consent denied or unavailable");
			current();
		}
		return JSON.stringify(
			sanitizeEvidence(
				await ports.invoke(name, { ...input, confirmRecord: true }),
			),
		);
	}
	if (name !== "analyze_function")
		return JSON.stringify(sanitizeEvidence(await ports.invoke(name, input)));
	const plan = (await ports.invoke(name, { ...input, phase: "prepare" })) as {
		id: string;
		requestHash: string;
		requirements: string[];
	};
	let cancelled = false;
	let cancellationError: unknown;
	const cancel = () => {
		if (cancelled) return;
		cancelled = true;
		try {
			ports.cancel(plan.id);
		} catch (error) {
			cancellationError = error;
		}
	};
	ports.signal?.addEventListener("abort", cancel, { once: true });
	try {
		current();
		if (
			!(await ports.review({
				operation: name,
				independentAnalysisApproval: true,
				plan,
			}))
		)
			throw new Error("Independent analysis approval denied or unavailable");
		current();
		const { executionToken } = ports.approve(plan);
		const result = await ports.invoke(name, {
			...input,
			phase: "run",
			planId: plan.id,
			executionToken,
		});
		return JSON.stringify(sanitizeEvidence(result));
	} catch (error) {
		cancel();
		if (cancellationError)
			throw new Error("Analysis cancellation could not be confirmed", {
				cause: cancellationError,
			});
		throw error;
	} finally {
		ports.signal?.removeEventListener("abort", cancel);
	}
}
