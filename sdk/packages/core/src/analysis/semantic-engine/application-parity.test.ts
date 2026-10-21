import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { expect, it } from "vitest";
import {
	analyzeApplicationSources,
	applicationArtifacts,
	APPLICATION_SCOPE,
} from "./application";
import { ownedApplication, ownedSource } from "./application.fixture";
import { digestCanonicalValue } from "./engine";
import { traceApplicationFeature } from "./upstream/src/domain/javascript/javascriptFeatureTrace";
import { compareJavaScriptApplicationVersions } from "./upstream/src/domain/javascript/javascriptApplicationVersionComparison";
import { compareJavaScriptExportShapes } from "./upstream/src/domain/javascript/javascriptExportShapeComparison";

const root = process.env.CLINE_SEMANTIC_REFERENCE_ROOT;
(root ? it : it.skip)(
	"matches the pinned application projection and saved-query algorithms over the same admitted bytes",
	async () => {
		const base = resolve(root!);
		const load = (p: string) =>
			import(/* @vite-ignore */ pathToFileURL(join(base, p)).href);
		const [
			analysisModule,
			builder,
			control,
			semanticModule,
			graphModule,
			traceModule,
			versionModule,
			exportsModule,
		] = await Promise.all(
			[
				"src/application/javascript/JavaScriptArtifactAnalysis.ts",
				"src/application/javascript/JavaScriptArtifactGraphBuilder.ts",
				"src/application/javascript/JavaScriptAnalysisControl.ts",
				"src/application/javascript/JavaScriptSemanticGraphBuilder.ts",
				"src/domain/javascript/javascriptApplicationGraph.ts",
				"src/domain/javascript/javascriptFeatureTrace.ts",
				"src/domain/javascript/javascriptApplicationVersionComparison.ts",
				"src/domain/javascript/javascriptExportShapeComparison.ts",
			].map(load),
		);
		const corpus = [
			ownedApplication(),
			ownedApplication(2),
			[
				ownedSource(
					"package.json",
					'{"type":"module","exports":{".":"./entry.js"}}',
				),
				ownedSource(
					"entry.js",
					'export {value} from "./value.js";import data from "./data.json" with {type:"json"};',
				),
				ownedSource("value.js", "export const value={answer:42};"),
				ownedSource("data.json", '{"owned":true}'),
			],
			[
				ownedSource(
					"bundle.js",
					'(function(modules){return modules[0]()})([function(){return "owned"}]);\n//# sourceMappingURL=bundle.js.map',
				),
				ownedSource(
					"bundle.js.map",
					JSON.stringify({
						version: 3,
						file: "bundle.js",
						sources: ["original.ts"],
						sourcesContent: ["export const owned=42;"],
						names: [],
						mappings: "AAAA",
					}),
				),
			],
			[
				ownedSource(
					"index.html",
					'<script type="module" src="./entry.js?owned=1"></script><script>window.owned=42</script>',
				),
				ownedSource(
					"entry.js",
					'import "./unknown.js";throw new Error("MUST_NOT_EXECUTE");',
				),
			],
			[
				ownedSource(
					"ambiguous.js",
					'function require(x){return x} const {ipcMain}=require("electron");ipcMain.handle("owned:add",()=>1);',
				),
				ownedSource("broken.js", "function broken( {"),
			],
		];
		const integrated = [];
		const originals = [];
		for (const sources of corpus) {
			const { snapshot, fileSet } = applicationArtifacts(sources);
			const projection =
				semanticModule.createJavaScriptSemanticGraphProjection();
			const analysis =
				await analysisModule.analyzeAndProjectJavaScriptArtifactFiles(
					fileSet,
					(f: unknown, ir: unknown) => projection.projectFileSteps(f, ir),
				);
			for (const item of analysis.files)
				if (item.file.kind === "javascript" && item.semantic === null)
					projection.recordUnavailableFile(
						item.file,
						item.file.text.included
							? "Source could not be parsed"
							: "Source text unavailable",
						null,
						"incomplete-module",
					);
			const full = await control.completeJavaScriptAnalysisSteps(
				builder.buildImmutableJavaScriptArtifactGraphSteps(
					snapshot,
					fileSet,
					analysis,
				),
			);
			const application = graphModule.createJavaScriptApplicationGraph({
				schema: full.schema,
				root_node_ids: full.root_node_ids,
				nodes: full.nodes,
				edges: full.edges,
				coverage: { ...full.coverage, status: "partial" },
				limitations: [...full.limitations, APPLICATION_SCOPE],
			});
			const semantic = await control.completeJavaScriptAnalysisSteps(
				projection.finishImmutableSteps(
					snapshot.manifest.root_sha256,
					application,
				),
			);
			const actual = await analyzeApplicationSources(sources);
			expect(digestCanonicalValue(actual.application)).toBe(
				digestCanonicalValue(application),
			);
			expect(digestCanonicalValue(actual.semantic)).toBe(
				digestCanonicalValue(semantic),
			);
			const traceInput = {
				sourceEvidenceId: `ev_${"1".repeat(64)}`,
				graph: actual.application,
				nativeEvidence: [],
				seed: { kind: "channel" as const, value: "owned:add" },
				direction: "both" as const,
			};
			expect(traceApplicationFeature(traceInput)).toEqual(
				traceModule.traceApplicationFeature({
					...traceInput,
					graph: application,
				}),
			);
			integrated.push(actual);
			originals.push({ application, semantic });
		}
		const versionInput = {
			left: {
				evidenceId: `ev_${"1".repeat(64)}`,
				rootArtifactSha256: integrated[0]!.semantic.root_artifact_sha256,
				graph: integrated[0]!.application,
			},
			right: {
				evidenceId: `ev_${"2".repeat(64)}`,
				rootArtifactSha256: integrated[1]!.semantic.root_artifact_sha256,
				graph: integrated[1]!.application,
			},
			leftNativeEvidence: [],
			rightNativeEvidence: [],
		};
		expect(compareJavaScriptApplicationVersions(versionInput)).toEqual(
			versionModule.compareJavaScriptApplicationVersions({
				...versionInput,
				left: { ...versionInput.left, graph: originals[0]!.application },
				right: { ...versionInput.right, graph: originals[1]!.application },
			}),
		);
		const exportInput = {
			left: { ...versionInput.left, modulePath: "api.cjs", exportName: "add" },
			right: {
				...versionInput.right,
				modulePath: "api.cjs",
				exportName: "add",
			},
		};
		expect(compareJavaScriptExportShapes(exportInput)).toEqual(
			exportsModule.compareJavaScriptExportShapes({
				...exportInput,
				left: { ...exportInput.left, graph: originals[0]!.application },
				right: { ...exportInput.right, graph: originals[1]!.application },
			}),
		);
		const provenance = JSON.parse(
			readFileSync(
				new URL("./upstream/PROVENANCE.json", import.meta.url),
				"utf8",
			),
		);
		for (const file of provenance.files)
			expect(
				createHash("sha256")
					.update(readFileSync(join(base, file.path)))
					.digest("hex"),
				file.path,
			).toBe(file.sha256);
	},
	60_000,
);
