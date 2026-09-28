import { describe, expect, it } from "bun:test";
import {
	evaluateParity,
	type ParityCorpus,
	type ParityRun,
} from "./codex-parity";

const corpus: ParityCorpus = {
	version: 1,
	scenarios: [
		{
			id: "repair",
			category: "coding",
			weight: 2,
			description: "Repair a repository",
		},
		{
			id: "computer",
			category: "computer-use",
			weight: 1,
			description: "Complete a UI task",
		},
	],
};

const candidate: ParityRun = {
	version: 1,
	commit: "candidate",
	environment: "windows",
	results: [
		{ scenarioId: "repair", score: 1, durationMs: 1_000, interventions: 0 },
		{ scenarioId: "computer", score: 0.5, durationMs: 2_000, interventions: 1 },
	],
};

describe("Codex parity benchmark", () => {
	it("computes weighted readiness and measured relative parity", () => {
		const reference: ParityRun = {
			version: 1,
			commit: "reference",
			environment: "windows",
			results: [
				{ scenarioId: "repair", score: 1, durationMs: 800, interventions: 0 },
				{
					scenarioId: "computer",
					score: 1,
					durationMs: 1_500,
					interventions: 0,
				},
			],
		};
		const report = evaluateParity(corpus, candidate, reference);
		expect(report.coveragePercent).toBe(100);
		expect(report.weightedCandidateScore).toBeCloseTo(5 / 6);
		expect(report.weightedReferenceScore).toBe(1);
		expect(report.parityPercent).toBeCloseTo((5 / 6) * 100);
		expect(report.totalDurationMs).toBe(3_000);
		expect(report.totalInterventions).toBe(1);
	});

	it("reports coverage without fabricating a Codex comparison", () => {
		const partial = { ...candidate, results: candidate.results.slice(0, 1) };
		const report = evaluateParity(corpus, partial);
		expect(report.coveragePercent).toBeCloseTo((2 / 3) * 100);
		expect(report.parityPercent).toBeUndefined();
	});

	it("rejects unknown, duplicate, and out-of-range results", () => {
		expect(() =>
			evaluateParity(corpus, {
				...candidate,
				results: [
					{ scenarioId: "unknown", score: 1, durationMs: 1, interventions: 0 },
				],
			}),
		).toThrow("Unknown");
		expect(() =>
			evaluateParity(corpus, {
				...candidate,
				results: [candidate.results[0], candidate.results[0]],
			}),
		).toThrow("Duplicate");
		expect(() =>
			evaluateParity(corpus, {
				...candidate,
				results: [{ ...candidate.results[0], score: 1.1 }],
			}),
		).toThrow("between 0 and 1");
	});

	it("requires comparable corpus versions, environments, and reference coverage", () => {
		expect(() => evaluateParity(corpus, { ...candidate, version: 2 })).toThrow(
			"does not match",
		);
		expect(() =>
			evaluateParity(corpus, candidate, {
				...candidate,
				commit: "reference",
				environment: "linux",
			}),
		).toThrow("environment");
		expect(() =>
			evaluateParity(corpus, candidate, {
				...candidate,
				commit: "reference",
				results: candidate.results.slice(0, 1),
			}),
		).toThrow("cover every");
	});
});
