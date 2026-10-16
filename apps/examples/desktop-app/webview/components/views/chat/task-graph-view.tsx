"use client";

import { useId, useMemo } from "react";
import type { SessionTaskReport, TaskReportStepStatus } from "@/lib/task-report";
import { buildTaskGraph, type TaskGraphNode } from "@/lib/task-graph";
import { cn } from "@/lib/utils";

const NODE_WIDTH = 188;
const NODE_HEIGHT = 82;
const LEVEL_GAP = 36;
const NODE_GAP = 18;
const GRAPH_PADDING = 20;

function statusLabel(status: TaskReportStepStatus): string {
	return {
		pending: "Pending",
		in_progress: "In progress",
		blocked: "Blocked",
		waiting_for_user: "Needs input",
		completed: "Completed",
		failed: "Failed",
		skipped: "Skipped",
		cancelled: "Cancelled",
	}[status];
}

function nodeTone(status: TaskReportStepStatus): string {
	switch (status) {
		case "completed":
			return "fill-emerald-500/10 stroke-emerald-500";
		case "in_progress":
			return "fill-blue-500/10 stroke-blue-500";
		case "failed":
		case "blocked":
			return "fill-destructive/10 stroke-destructive";
		case "waiting_for_user":
			return "fill-amber-500/10 stroke-amber-500";
		default:
			return "fill-background stroke-border";
	}
}

function statusDotTone(status: TaskReportStepStatus): string {
	switch (status) {
		case "completed":
			return "fill-emerald-500";
		case "in_progress":
			return "fill-blue-500";
		case "failed":
		case "blocked":
			return "fill-destructive";
		case "waiting_for_user":
			return "fill-amber-500";
		default:
			return "fill-muted-foreground";
	}
}

function labelLines(label: string): string[] {
	const words = label.trim().split(/\s+/);
	const lines: string[] = [];
	for (const word of words) {
		const current = lines.at(-1) ?? "";
		if (!current || `${current} ${word}`.length <= 26) {
			if (current) lines[lines.length - 1] = `${current} ${word}`;
			else lines.push(word);
		} else if (lines.length < 2) {
			lines.push(word);
		} else {
			lines[1] = `${lines[1].slice(0, 22)}…`;
			break;
		}
	}
	return lines.slice(0, 2);
}

function nodeTitle(node: TaskGraphNode): string {
	const kind = node.kind === "command" ? "Command" : node.stepKind ?? "Step";
	return `${kind}: ${node.label} — ${statusLabel(node.status)}${node.detail ? ` — ${node.detail}` : ""}`;
}

export function TaskGraphView({ report }: { report: SessionTaskReport }) {
	const markerId = `task-graph-arrow-${useId().replaceAll(":", "")}`;
	const graph = useMemo(() => buildTaskGraph(report), [report]);
	const positions = useMemo(() => {
		const result = new Map<string, { x: number; y: number }>();
		for (const [level, nodes] of graph.levels.entries()) {
			for (const [index, node] of nodes.entries()) {
				result.set(node.id, {
					x: GRAPH_PADDING + level * (NODE_WIDTH + LEVEL_GAP),
					y: GRAPH_PADDING + index * (NODE_HEIGHT + NODE_GAP),
				});
			}
		}
		return result;
	}, [graph.levels]);
	const width = Math.max(
		NODE_WIDTH + GRAPH_PADDING * 2,
		graph.levels.length * NODE_WIDTH +
			Math.max(0, graph.levels.length - 1) * LEVEL_GAP +
			GRAPH_PADDING * 2,
	);
	const maxNodes = Math.max(1, ...graph.levels.map((level) => level.length));
	const height =
		GRAPH_PADDING * 2 + maxNodes * NODE_HEIGHT + (maxNodes - 1) * NODE_GAP;

	if (graph.nodes.length === 0) {
		return (
			<div className="rounded-xl border border-dashed px-3 py-6 text-center text-xs text-muted-foreground">
				The command graph will appear when execution evidence arrives.
			</div>
		);
	}

	return (
		<section aria-label="Task execution graph" data-testid="task-graph">
			<div className="mb-2 flex items-baseline justify-between gap-3">
				<div>
					<h3 className="text-xs font-semibold uppercase tracking-[0.14em] text-muted-foreground">
						Execution graph
					</h3>
					<p className="mt-1 text-[11px] text-muted-foreground">
						{report.mode === "activity"
							? "Commands are ordered as live evidence arrives."
							: "Dependencies and command evidence for this task."}
					</p>
				</div>
				<span className="shrink-0 text-[11px] tabular-nums text-muted-foreground">
					{graph.nodes.length} {graph.nodes.length === 1 ? "node" : "nodes"}
				</span>
			</div>
			<div className="overflow-x-auto rounded-xl border border-border/60 bg-muted/20 px-1 py-1">
				<svg
					aria-label="Task execution dependency graph"
					className="block"
					height={height}
					role="img"
					viewBox={`0 0 ${width} ${height}`}
					width={width}
				>
					<title>Task execution dependency graph</title>
					<defs>
						<marker
							id={markerId}
							markerHeight="7"
							markerUnits="strokeWidth"
							markerWidth="7"
							orient="auto-start-reverse"
							refX="7"
							refY="3.5"
						>
							<path className="fill-muted-foreground" d="M0,0 L7,3.5 L0,7 z" />
						</marker>
					</defs>
					{graph.edges.map((edge) => {
						const from = positions.get(edge.from);
						const to = positions.get(edge.to);
						if (!from || !to) return null;
						const startX = from.x + NODE_WIDTH;
						const startY = from.y + NODE_HEIGHT / 2;
						const endX = to.x;
						const endY = to.y + NODE_HEIGHT / 2;
						const bend = Math.max(20, (endX - startX) / 2);
						return (
							<path
								className="fill-none stroke-border"
								d={`M ${startX} ${startY} C ${startX + bend} ${startY}, ${endX - bend} ${endY}, ${endX} ${endY}`}
								key={`${edge.from}-${edge.to}`}
								markerEnd={`url(#${markerId})`}
								strokeWidth="1.5"
							/>
						);
					})}
					{graph.nodes.map((node) => {
						const position = positions.get(node.id);
						if (!position) return null;
						const lines = labelLines(node.label);
						return (
							<g
								aria-label={nodeTitle(node)}
								key={node.id}
								role="group"
								transform={`translate(${position.x}, ${position.y})`}
							>
								<title>{nodeTitle(node)}</title>
								<rect
									className={cn(nodeTone(node.status))}
									height={NODE_HEIGHT}
									rx="12"
									strokeWidth="1.2"
									width={NODE_WIDTH}
								/>
								<circle
									className={statusDotTone(node.status)}
									cx="16"
									cy="17"
									r="4"
								/>
								<text
									className="fill-muted-foreground"
									fontSize="9"
									x="27"
									y="20"
								>
									{node.kind === "command" ? "COMMAND" : node.stepKind?.toUpperCase()}
								</text>
								{lines.map((line, index) => (
									<text
										className="fill-foreground"
										fontSize="12"
										fontWeight="500"
										key={`${node.id}-${index}`}
										x="14"
										y={39 + index * 15}
									>
										{line}
									</text>
								))}
								{node.detail ? (
									<text
										className="fill-muted-foreground"
										fontSize="9"
										x="14"
										y="73"
									>
										{node.detail.slice(0, 28)}
										{node.detail.length > 28 ? "…" : ""}
									</text>
								) : null}
							</g>
						);
					})}
				</svg>
			</div>
		</section>
	);
}
