import { describe, expect, it } from "vitest";
import {
	extractArtifactPaths,
	isCodeArtifactPath,
	isInlinePreviewArtifactPath,
	parseArtifactReference,
} from "./artifact-paths";

describe("artifact paths", () => {
	it("finds Windows artifacts with spaces without swallowing surrounding prose", () => {
		expect(
			extractArtifactPaths(
				"Found it at C:\\Users\\Paul\\Downloads\\My IP_260415_apks.apk (10 MB).",
			),
		).toEqual(["C:\\Users\\Paul\\Downloads\\My IP_260415_apks.apk"]);
	});

	it("distinguishes editor files from system-opened artifacts", () => {
		expect(isCodeArtifactPath("src/app.ts")).toBe(true);
		expect(isCodeArtifactPath("build/app-release.apk")).toBe(false);
		expect(isInlinePreviewArtifactPath("C:\\work\\PATCH_REPORT.md")).toBe(true);
		expect(isInlinePreviewArtifactPath("build/app-release.apk")).toBe(false);
		expect(parseArtifactReference("src/app.ts:42:7")).toEqual({
			path: "src/app.ts",
			line: 42,
			column: 7,
		});
	});
});
