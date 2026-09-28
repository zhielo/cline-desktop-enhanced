import { readFileSync, writeFileSync } from "node:fs";

export type ParityScenario = {
	id: string;
	category: string;
	weight: number;
	description: string;
	platform?: "any" | "windows";
};

export type ParityCorpus = {
	version: number;
	scenarios: ParityScenario[];
};

export type ParityResult = {
	scenarioId: string;
	score: number;
	durationMs: number;
	interventions: number;
	inputTokens?: number;
	outputTokens?: number;
	costUnits?: number;
};

export type ParityRun = {
	version: number;
	commit: string;
	environment: string;
	results: ParityResult[];
};

export type CategoryScore = {
	category: string;
	weight: number;
	candidateScore: number;
	referenceScore?: number;
	parityPercent?: number;
};

export type ParityReport = {
	corpusVersion: number;
	candidateCommit: string;
	referenceCommit?: string;
	coveragePercent: number;
	weightedCandidateScore: number;
	weightedReferenceScore?: number;
	parityPercent?: number;
	totalDurationMs: number;
	totalInterventions: number;
	categories: CategoryScore[];
};

function assertFiniteRange(
	value: number,
	min: number,
	max: number,
	label: string,
): void {
	if (!Number.isFinite(value) || value < min || value > max) {
		throw new Error(`${label} must be between ${min} and ${max}`);
	}
}

function validateCorpus(corpus: ParityCorpus): void {
	if (!Number.isInteger(corpus.version) || corpus.version < 1) {
		throw new Error("Corpus version must be a positive integer");
	}
	if (!Array.isArray(corpus.scenarios) || corpus.scenarios.length === 0) {
		throw new Error("Parity corpus must contain scenarios");
	}
	const ids = new Set<string>();
	for (const scenario of corpus.scenarios) {
		if (!scenario.id.trim() || ids.has(scenario.id)) {
			throw new Error(`Duplicate or empty scenario ID: ${scenario.id}`);
		}
		ids.add(scenario.id);
		if (!scenario.category.trim())
			throw new Error(`Scenario ${scenario.id} has no category`);
		assertFiniteRange(
			scenario.weight,
			Number.MIN_VALUE,
			100,
			`Weight for ${scenario.id}`,
		);
	}
}

function indexRun(
	corpus: ParityCorpus,
	run: ParityRun,
): Map<string, ParityResult> {
	if (run.version !== corpus.version) {
		throw new Error(
			`Run corpus version ${run.version} does not match corpus version ${corpus.version}`,
		);
	}
	if (!run.commit.trim() || !run.environment.trim()) {
		throw new Error("Parity runs require commit and environment identifiers");
	}
	const known = new Set(corpus.scenarios.map((scenario) => scenario.id));
	const indexed = new Map<string, ParityResult>();
	for (const result of run.results) {
		if (!known.has(result.scenarioId)) {
			throw new Error(`Unknown parity scenario: ${result.scenarioId}`);
		}
		if (indexed.has(result.scenarioId)) {
			throw new Error(`Duplicate parity result: ${result.scenarioId}`);
		}
		assertFiniteRange(result.score, 0, 1, `Score for ${result.scenarioId}`);
		assertFiniteRange(
			result.durationMs,
			0,
			Number.MAX_SAFE_INTEGER,
			`Duration for ${result.scenarioId}`,
		);
		assertFiniteRange(
			result.interventions,
			0,
			Number.MAX_SAFE_INTEGER,
			`Interventions for ${result.scenarioId}`,
		);
		for (const [name, value] of [
			["inputTokens", result.inputTokens],
			["outputTokens", result.outputTokens],
			["costUnits", result.costUnits],
		] as const) {
			if (value !== undefined) {
				assertFiniteRange(
					value,
					0,
					Number.MAX_SAFE_INTEGER,
					`${name} for ${result.scenarioId}`,
				);
			}
		}
		indexed.set(result.scenarioId, result);
	}
	return indexed;
}

export function evaluateParity(
	corpus: ParityCorpus,
	candidate: ParityRun,
	reference?: ParityRun,
): ParityReport {
	validateCorpus(corpus);
	const candidateById = indexRun(corpus, candidate);
	const referenceById = reference ? indexRun(corpus, reference) : undefined;
	if (reference && reference.environment !== candidate.environment) {
		throw new Error(
			`Candidate environment ${candidate.environment} does not match reference environment ${reference.environment}`,
		);
	}
	if (referenceById && referenceById.size !== corpus.scenarios.length) {
		throw new Error("Reference run must cover every parity scenario");
	}
	const totalWeight = corpus.scenarios.reduce(
		(sum, scenario) => sum + scenario.weight,
		0,
	);
	const coveredWeight = corpus.scenarios.reduce(
		(sum, scenario) =>
			sum + (candidateById.has(scenario.id) ? scenario.weight : 0),
		0,
	);
	const categoryNames = [
		...new Set(corpus.scenarios.map((scenario) => scenario.category)),
	];
	const categories = categoryNames.map((category): CategoryScore => {
		const scenarios = corpus.scenarios.filter(
			(scenario) => scenario.category === category,
		);
		const weight = scenarios.reduce(
			(sum, scenario) => sum + scenario.weight,
			0,
		);
		const candidateScore =
			scenarios.reduce(
				(sum, scenario) =>
					sum + (candidateById.get(scenario.id)?.score ?? 0) * scenario.weight,
				0,
			) / weight;
		const referenceScore = referenceById
			? scenarios.reduce(
					(sum, scenario) =>
						sum +
						(referenceById.get(scenario.id)?.score ?? 0) * scenario.weight,
					0,
				) / weight
			: undefined;
		return {
			category,
			weight,
			candidateScore,
			referenceScore,
			parityPercent:
				referenceScore && referenceScore > 0
					? Math.min(100, (candidateScore / referenceScore) * 100)
					: undefined,
		};
	});
	const weightedCandidateScore =
		categories.reduce(
			(sum, category) => sum + category.candidateScore * category.weight,
			0,
		) / totalWeight;
	const weightedReferenceScore = referenceById
		? categories.reduce(
				(sum, category) =>
					sum + (category.referenceScore ?? 0) * category.weight,
				0,
			) / totalWeight
		: undefined;
	return {
		corpusVersion: corpus.version,
		candidateCommit: candidate.commit,
		referenceCommit: reference?.commit,
		coveragePercent: (coveredWeight / totalWeight) * 100,
		weightedCandidateScore,
		weightedReferenceScore,
		parityPercent:
			weightedReferenceScore && weightedReferenceScore > 0
				? Math.min(100, (weightedCandidateScore / weightedReferenceScore) * 100)
				: undefined,
		totalDurationMs: [...candidateById.values()].reduce(
			(sum, result) => sum + result.durationMs,
			0,
		),
		totalInterventions: [...candidateById.values()].reduce(
			(sum, result) => sum + result.interventions,
			0,
		),
		categories,
	};
}

function readJson<T>(path: string): T {
	return JSON.parse(readFileSync(path, "utf8")) as T;
}

if (import.meta.main) {
	const args = process.argv.slice(2);
	const value = (name: string): string | undefined => {
		const index = args.indexOf(name);
		return index >= 0 ? args[index + 1] : undefined;
	};
	const corpusPath = value("--corpus");
	const candidatePath = value("--candidate");
	const referencePath = value("--reference");
	const outputPath = value("--output");
	if (!corpusPath || !candidatePath) {
		console.error(
			"Usage: bun evals/parity/codex-parity.ts --corpus <corpus.json> --candidate <run.json> [--reference <codex-run.json>] [--output <report.json>]",
		);
		process.exit(2);
	}
	const report = evaluateParity(
		readJson<ParityCorpus>(corpusPath),
		readJson<ParityRun>(candidatePath),
		referencePath ? readJson<ParityRun>(referencePath) : undefined,
	);
	const serialized = `${JSON.stringify(report, null, 2)}\n`;
	if (outputPath) writeFileSync(outputPath, serialized);
	else process.stdout.write(serialized);
}
