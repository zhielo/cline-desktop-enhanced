import { describe, expect, it } from "vitest";
import {
	createStreamingSecretRedactor,
	isSensitiveEnvironmentVariable,
	prepareProcessEnvironment,
	redactSensitiveText,
} from "./process-environment-policy";

describe("process environment policy", () => {
	it.each([
		"GITHUB_TOKEN",
		"openai_api_key",
		"AWS_SECRET_ACCESS_KEY",
		"MY_REFRESH_TOKEN",
		"database_url",
		"OTEL_EXPORTER_OTLP_HEADERS",
	])("classifies %s as sensitive", (name) => {
		expect(isSensitiveEnvironmentVariable(name, "credential-value")).toBe(true);
	});

	it("does not misclassify normal developer variables", () => {
		expect(isSensitiveEnvironmentVariable("PATH", "/usr/bin")).toBe(false);
		expect(isSensitiveEnvironmentVariable("PWD", "/workspace")).toBe(false);
		expect(isSensitiveEnvironmentVariable("USERPROFILE", "C:\\Users\\me")).toBe(
			false,
		);
		expect(isSensitiveEnvironmentVariable("CLINE_DATA_DIR", "/tmp/data")).toBe(
			false,
		);
	});

	it("treats a credential-bearing proxy URL as sensitive", () => {
		expect(
			isSensitiveEnvironmentVariable(
				"HTTPS_PROXY",
				"https://user:password@proxy.example.test",
			),
		).toBe(true);
	});

	it("filters inherited and override secrets unless explicitly granted", () => {
		const filtered = prepareProcessEnvironment({
			baseEnvironment: {
				PATH: "/usr/bin",
				GITHUB_TOKEN: "github-secret-value",
			},
			overrides: {
				SAFE_FLAG: "enabled",
				API_KEY: "override-secret-value",
			},
		});
		expect(filtered.environment).toEqual({
			PATH: "/usr/bin",
			SAFE_FLAG: "enabled",
		});
		expect(filtered.omittedSensitiveNames).toEqual(["API_KEY", "GITHUB_TOKEN"]);
		expect(filtered.secretValues).toEqual(
			expect.arrayContaining(["github-secret-value", "override-secret-value"]),
		);

		const granted = prepareProcessEnvironment({
			baseEnvironment: { GITHUB_TOKEN: "github-secret-value" },
			allowedSensitiveEnvironmentVariables: ["github_token"],
		});
		expect(granted.environment.GITHUB_TOKEN).toBe("github-secret-value");
		expect(granted.secretValues).toContain("github-secret-value");
	});

	it("redacts short granted credentials rather than trading secrecy for output fidelity", () => {
		const prepared = prepareProcessEnvironment({
			baseEnvironment: { API_KEY: "1234" },
			allowedSensitiveEnvironmentVariables: ["API_KEY"],
		});
		expect(redactSensitiveText("credential=1234", prepared.secretValues)).toBe(
			"credential=[REDACTED]",
		);
	});

	it("redacts assignments, authorization, credential URLs, tokens, and keys", () => {
		const privateKey =
			"-----BEGIN PRIVATE KEY-----\nabc123\n-----END PRIVATE KEY-----";
		const output = redactSensitiveText(
			[
				"api_key=visible-secret",
				"Authorization: Bearer abc.def.ghi",
				"https://user:pass@example.test/path",
				"ghp_abcdefghijklmnopqrstuvwxyz123456",
				privateKey,
				"exact-known-value",
			].join("\n"),
			["exact-known-value"],
		);
		expect(output).not.toContain("visible-secret");
		expect(output).not.toContain("abc.def.ghi");
		expect(output).not.toContain("user:pass");
		expect(output).not.toContain("ghp_");
		expect(output).not.toContain("abc123");
		expect(output).not.toContain("exact-known-value");
		expect(output.match(/\[REDACTED\]/g)?.length).toBeGreaterThanOrEqual(6);
	});

	it("redacts an exact secret split across output chunks", () => {
		const redactor = createStreamingSecretRedactor(["split-secret-value"]);
		const output = [
			redactor.push("before split-sec"),
			redactor.push("ret-value after"),
			redactor.finish(),
		].join("");
		expect(output).toBe("before [REDACTED] after");
	});

	it("holds and redacts a sensitive assignment split across chunks", () => {
		const redactor = createStreamingSecretRedactor();
		const output = [
			redactor.push("before\ntoken=split-"),
			redactor.push("value\nafter"),
			redactor.finish(),
		].join("");
		expect(output).toBe("before\ntoken=[REDACTED]\nafter");
	});
});
