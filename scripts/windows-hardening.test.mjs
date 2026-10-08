import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { supportedBunVersion } from "./read-bun-version.mjs";

const load = (path) =>
	readFileSync(new URL(`../${path}`, import.meta.url), "utf8");
test("supported Bun has one exact canonical package metadata value", () => {
	expect(supportedBunVersion(JSON.parse(load("package.json")))).toBe("1.3.14");
	expect(() =>
		supportedBunVersion({
			packageManager: "bun@latest",
			engines: { bun: "1.3.14" },
		}),
	).toThrow();
	expect(() =>
		supportedBunVersion({
			packageManager: "bun@1.3.14",
			engines: { bun: "1.3.13" },
		}),
	).toThrow();
	for (const path of [
		".github/workflows/build-custom-windows-installer.yml",
		".github/workflows/custom-desktop-validation.yml",
		".github/workflows/desktop-test.yml",
		".github/workflows/sdk-test.yml",
	]) {
		expect(load(path)).toContain("scripts/read-bun-version.mjs");
		expect(load(path)).toContain(
			"bun-version: ${{ steps.toolchain.outputs.version }}",
		);
	}
});
test("every main PR gets an unsigned installer gate without signing secrets or publication", () => {
	const source = load(".github/workflows/build-custom-windows-installer.yml");
	expect(source).toContain("pull_request:\n    branches: [main]");
	expect(source).toContain('"fix/**"');
	expect(source).not.toContain("pull_request_target");
	expect(source).not.toContain("WINDOWS_CERTIFICATE");
	expect(source).not.toContain("gh release create");
	expect(source).not.toContain("contents: write");
	expect(source).toContain("steps.ui_acceptance.outcome == 'success'");
	expect(source).toContain("validate:advanced --engines");
	expect(source).toContain("installed-ui-acceptance.ts");
});
test("PR regression has no path-filter blind spots and one blocking validator", () => {
	const source = load(".github/workflows/custom-desktop-validation.yml");
	expect(source).not.toContain("paths:");
	expect(source).toContain("run: bun run validate:advanced");
	expect(source).not.toContain("continue-on-error");
});
test("upstream JetBrains dispatch does not demand upstream App credentials on desktop forks", () => {
	const source = load(".github/workflows/ext-jb-test-integration.yml");
	expect(source).toContain("github.repository == 'cline/cline'");
	expect(source).toContain("vars.CLINE_JETBRAINS_APP_ID != ''");
	expect(source).toContain("github.event.pull_request.author_association");
	expect(source).toContain("github.event.comment.author_association");
	expect(source).toContain("curl --fail-with-body");
	expect(source).not.toContain("actions/checkout");
	expect(source).not.toContain("continue-on-error");
});
test("setup installs only with explicit consent and fails before changing interpreter", () => {
	const source = load("scripts/setup-analysis-environment.ps1");
	expect(source).toContain("if (-not $Apply)");
	expect(source).toContain("CLINE_RE_PYTHON was not changed");
	expect(source).toContain("-I -c");
});
test("installed UI acceptance uses installed Tauri transport and fixture-only configuration", () => {
	const source = load("apps/vscode/scripts/desktop-installed-acceptance.ts");
	expect(source).toContain("CLINE_TEST_INSTALLED_APP");
	expect(source).toContain("get_desktop_backend_endpoint");
	expect(source).toContain("WEBVIEW2_USER_DATA_FOLDER");
	expect(source).toContain("restart-setting-and-session-persistence-passed");
	expect(source).toContain("No dev web server");
});
test("installed UI consumes verified smoke paths rather than quoted registry paths", () => {
	const workflow = load(".github/workflows/build-custom-windows-installer.yml");
	expect(workflow).toContain(
		'"CLINE_TEST_INSTALLED_APP=$($appExe.FullName)" >> $env:GITHUB_ENV',
	);
	expect(workflow).toContain(
		'"CLINE_TEST_INSTALLED_SIDECAR=$($sidecarExe.FullName)" >> $env:GITHUB_ENV',
	);
	const ui = workflow
		.split("name: Installed WebView acceptance journey")[1]
		.split("name: Upload installed UI")[0];
	expect(ui).not.toContain("Get-ItemProperty");
	expect(ui).not.toContain("InstallLocation");
	expect(ui).toContain("IsPathFullyQualified");
	expect(ui).toContain("Test-Path -LiteralPath $path -PathType Leaf");
	expect(workflow).toContain("steps.ui_acceptance.outcome == 'success'");
});
test("pinned packaging installation retries are bounded and exhaustion fails closed", () => {
	const source = load("scripts/install-pinned-windows-tool.ps1");
	expect(source).toContain("$attempt -le 3");
	expect(source).toContain('"--version=$Version"');
	expect(source).toContain("if ($code -eq 0) { return }");
	expect(source).toContain("throw");
	expect(source).toContain("failed after 3 attempts");
	expect(source).not.toContain("continue-on-error");
	const workflow = load(".github/workflows/build-custom-windows-installer.yml");
	expect(workflow).toContain("scripts/install-pinned-windows-tool.test.ps1");
	expect(workflow).toContain("steps.consolidated.outcome == 'failure'");
	expect(workflow).toContain("if-no-files-found: error");
});
