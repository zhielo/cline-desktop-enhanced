import type {
	SessionTaskReport,
	TaskEvidenceStatus,
	TaskReportStepStatus,
} from "./task-report";

export type TaskGraphNode = {
	id: string;
	label: string;
	detail?: string;
	status: TaskReportStepStatus;
	kind: "step" | "command";
	stepKind?: string;
	index: number;
	level: number;
};

export type TaskGraphEdge = {
	from: string;
	to: string;
};

export type TaskGraph = {
	nodes: TaskGraphNode[];
	edges: TaskGraphEdge[];
	levels: TaskGraphNode[][];
};

function evidenceStatus(status: TaskEvidenceStatus): TaskReportStepStatus {
	switch (status) {
		case "running":
			return "in_progress";
		case "failed":
			return "failed";
		case "completed":
			return "completed";
	}
}

function compactDetail(value: string | undefined): string | undefined {
	if (!value?.trim()) return undefined;
	const compact = value.trim().replaceAll(/\s+/g, " ");
	return compact.length > 96 ? `${compact.slice(0, 93)}…` : compact;
}

function graphLevels(
	nodes: TaskGraphNode[],
	edges: TaskGraphEdge[],
): TaskGraphNode[][] {
	const parents = new Map<string, string[]>();
	for (const edge of edges) {
		const current = parents.get(edge.to) ?? [];
		current.push(edge.from);
		parents.set(edge.to, current);
	}
	const memo = new Map<string, number>();
	const visiting = new Set<string>();
	const levelFor = (id: string): number => {
		const cached = memo.get(id);
		if (cached !== undefined) return cached;
		if (visiting.has(id)) return 0;
		visiting.add(id);
		const level = Math.max(
			0,
			...(parents.get(id) ?? []).map((parent) => levelFor(parent) + 1),
		);
		visiting.delete(id);
		memo.set(id, level);
		return level;
	};

	const levels: TaskGraphNode[][] = [];
	for (const node of nodes) {
		const level = levelFor(node.id);
		node.level = level;
		(levels[level] ??= []).push(node);
	}
	return levels.filter((level): level is TaskGraphNode[] => Boolean(level));
}

/**
 * Projects the existing task report into a small, deterministic execution DAG.
 * Explicit parent relationships win. If the planner did not provide them, the
 * ordered steps/evidence become a linear execution path for a useful live view.
 */
export function buildTaskGraph(report: SessionTaskReport): TaskGraph {
	const hasSteps = report.steps.length > 0;
	const evidenceByStep = new Map<string, typeof report.evidence>();
	for (const evidence of report.evidence) {
		if (!evidence.stepId) continue;
		const items = evidenceByStep.get(evidence.stepId) ?? [];
		items.push(evidence);
		evidenceByStep.set(evidence.stepId, items);
	}

	const nodes: TaskGraphNode[] = hasSteps
		? report.steps.map((step, index) => {
			const evidence = evidenceByStep.get(step.id)?.[0];
			return {
				id: step.id,
				label: step.label,
				detail: compactDetail(
					evidence
						? `${evidence.label}${evidence.detail ? ` · ${evidence.detail}` : ""}`
						: undefined,
				),
				status: step.status,
				kind: "step",
				stepKind: step.kind,
				index,
				level: 0,
			};
		})
		: [...report.evidence]
				.reverse()
				.map((evidence, index) => ({
					id: evidence.id,
					label: evidence.label,
					detail: compactDetail(evidence.detail),
					status: evidenceStatus(evidence.status),
					kind: "command" as const,
					index,
					level: 0,
				}));

	if (nodes.length === 0) {
		return { nodes: [], edges: [], levels: [] };
	}

	const nodeIds = new Set(nodes.map((node) => node.id));
	const explicitEdges = hasSteps
		? report.steps.flatMap((step) =>
				step.parentStepId && nodeIds.has(step.parentStepId)
					? [{ from: step.parentStepId, to: step.id }]
					: [],
			)
		: [];
	const edges =
		explicitEdges.length > 0
			? explicitEdges
			: nodes.slice(1).map((node, index) => ({
					from: nodes[index].id,
					to: node.id,
				}));

	return { nodes, edges, levels: graphLevels(nodes, edges) };
}
