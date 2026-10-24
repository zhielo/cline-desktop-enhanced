/** Scripted loopback transport preflight. This is NOT a live-model evaluation. */
import http from "node:http";
import { spawn } from "node:child_process";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import assert from "node:assert/strict";

if (process.platform !== "linux")
	throw new Error("Owned source-host preflight requires Linux");
const repo = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const scratch = await mkdtemp(join(tmpdir(), "cline-model-preflight-"));
const report = join(scratch, "report.json");
const counts = { requests: 0, protocolErrors: 0 };
function decode(value) {
	return typeof value === "string" ? JSON.parse(value) : value;
}
function object(value) {
	assert(value && typeof value === "object" && !Array.isArray(value));
	return value;
}
function toolOutput(message) {
	assert.equal(message.role, "tool");
	return object(decode(message.content));
}
function choose(messages) {
	const user = messages.find((m) => m.role === "user");
	assert(user);
	const bundle = JSON.stringify(user.content).includes(
		"Inspect owned-bundle.js",
	);
	assert(
		bundle ||
			JSON.stringify(user.content).includes("Inspect owned-carchive.bin"),
	);
	const tools = messages.filter((m) => m.role === "tool");
	assert(tools.length <= 3, "Unexpected retry/tool call");
	if (tools.length === 0)
		return {
			name: "open_binary",
			args: { target: bundle ? "owned-bundle.js" : "owned-carchive.bin" },
		};
	if (tools.length === 1) {
		const artifact = toolOutput(tools[0]);
		assert.match(artifact.id, /^[a-f0-9-]{36}$/);
		assert.match(artifact.sha256, /^[a-f0-9]{64}$/);
		return {
			name: bundle ? "recover_bundle_sources" : "inspect_artifact_metadata",
			args: {
				artifactId: artifact.id,
				...(!bundle ? { reader: "pyinstaller" } : {}),
			},
		};
	}
	if (tools.length === 2) {
		const receipt = toolOutput(tools[1]).result;
		assert(["partial", "completed"].includes(receipt.status));
		return {
			name: "reverse_engineer",
			args: {
				operation: "analysis_evidence",
				evidence_query: {
					receiptId: receipt.id,
					view: bundle ? "bundle-recovery" : "artifact-metadata",
					limit: 50,
				},
			},
		};
	}
	const page = toolOutput(tools[2]);
	assert.equal(page.available, true);
	assert.equal(page.truncated, false);
	assert.equal(page.nextOffset, null);
	assert(Array.isArray(page.items));
	const answer = {
		kind: bundle ? "bundle-factories" : "pyinstaller-carchive",
		receiptId: page.id,
		sourceSha256: bundle ? page.sourceSha256 : page.inputSha256,
		targetExecuted: false,
		verifiedBehavior: false,
	};
	if (bundle)
		Object.assign(answer, {
			count: page.total,
			completeSourceRecovered: false,
		});
	else {
		const scalar = (path) => {
			const entry = page.items.find((r) => r.path === path);
			assert(
				entry,
				"Missing declared metadata; no known-answer fallback allowed",
			);
			return decode(entry.valueJson);
		};
		Object.assign(answer, {
			entryName: scalar("/entries/0/name"),
			pythonVersion: scalar("/pythonVersion"),
			decodedPayload: false,
		});
	}
	return { answer };
}
const server = http.createServer(async (req, res) => {
	try {
		assert.equal(req.method, "POST");
		assert.equal(req.url, "/v1/chat/completions");
		assert(++counts.requests <= 8, "Request budget exceeded");
		let body = "";
		for await (const part of req) {
			body += part;
			assert(
				Buffer.byteLength(body) <= 2_000_000,
				"Request byte budget exceeded",
			);
		}
		const input = object(JSON.parse(body));
		assert.equal(input.model, "owned-transport-fixture");
		const next = choose(input.messages);
		const toolCalls = next.name
			? [
					{
						index: 0,
						id: "owned_call_" + counts.requests,
						type: "function",
						function: {
							name: next.name,
							arguments: JSON.stringify(next.args),
						},
					},
				]
			: undefined;
		const base = {
			id: "owned_fixture_" + counts.requests,
			created: Math.floor(Date.now() / 1000),
			model: input.model,
		};
		assert.equal(input.stream, true);
		res.writeHead(200, { "content-type": "text/event-stream" });
		const chunk = (delta, finish_reason) =>
			"data: " +
			JSON.stringify({
				...base,
				object: "chat.completion.chunk",
				choices: [{ index: 0, delta, finish_reason }],
			}) +
			"\n\n";
		res.write(
			chunk(
				next.name
					? { role: "assistant", tool_calls: toolCalls }
					: { role: "assistant", content: JSON.stringify(next.answer) },
				null,
			),
		);
		res.end(chunk({}, next.name ? "tool_calls" : "stop") + "data: [DONE]\n\n");
	} catch {
		counts.protocolErrors++;
		// Never log requests, prompts, content, headers or credentials.
		res.writeHead(400, { "content-type": "application/json" });
		res.end(
			JSON.stringify({
				error: {
					message: "Owned preflight protocol mismatch",
					type: "fixture_error",
				},
			}),
		);
	}
});
server.requestTimeout = 15_000;
server.headersTimeout = 10_000;
let child;
let timer;
let output = "";
let exitCode = 1;
try {
	await new Promise((done, fail) => {
		server.once("error", fail);
		server.listen(0, "127.0.0.1", done);
	});
	const env = { ...process.env };
	for (const key of Object.keys(env))
		if (key.startsWith("CLINE_INVESTIGATION_EVAL_")) delete env[key];
	Object.assign(env, {
		CLINE_LIVE_INVESTIGATION_EVAL: "1",
		CLINE_INVESTIGATION_EVAL_MODE: "scripted-preflight",
		CLINE_INVESTIGATION_EVAL_PROVIDER: "openai-compatible",
		CLINE_INVESTIGATION_EVAL_MODEL: "owned-transport-fixture",
		CLINE_INVESTIGATION_EVAL_API_KEY: "owned-nonsecret-fixture",
		CLINE_INVESTIGATION_EVAL_BASE_URL:
			"http://127.0.0.1:" + server.address().port + "/v1",
		CLINE_INVESTIGATION_EVAL_REPORT: report,
	});
	child = spawn(
		"bun",
		[
			"x",
			"vitest",
			"run",
			"--config",
			"vitest.config.mts",
			"sidecar/investigation-model.live.test.ts",
		],
		{
			cwd: join(repo, "apps/examples/desktop-app"),
			detached: true,
			env,
			stdio: ["ignore", "pipe", "pipe"],
		},
	);
	const retain = (part) => {
		output = (output + part.toString()).slice(-16_000);
	};
	child.stdout.on("data", retain);
	child.stderr.on("data", retain);
	timer = setTimeout(() => {
		try {
			process.kill(-child.pid, "SIGKILL");
		} catch {
			/* already gone */
		}
	}, 480_000);
	const status = await new Promise((done, fail) => {
		child.once("error", fail);
		child.once("exit", done);
	});
	assert.equal(status, 0, "Production transport preflight failed");
	const result = JSON.parse(await readFile(report, "utf8"));
	assert.equal(
		result.execution,
		"scripted-transport-preflight-production-agent-and-host-tools",
	);
	assert.equal(result.liveModel, false);
	assert.equal(result.passed, true);
	assert.equal(result.results.length, 2);
	assert.equal(counts.requests, 8);
	assert.equal(counts.protocolErrors, 0);
	for (const row of result.results) {
		assert.equal(row.status, "completed");
		assert.equal(row.score, 1);
		assert.equal(row.passed, true);
		assert.equal(row.toolCalls.length, 3);
	}
	console.log(
		"PASS: 2 scripted transport journeys, 8 HTTP requests, exact retained evidence. NOT live-model or installed-Windows validation.",
	);
	exitCode = 0;
} catch (error) {
	console.error(
		error instanceof Error ? error.message : "Owned preflight failed",
	);
	// Only synthetic test logs: never emit server requests/headers or a real-provider response.
	console.error(output);
} finally {
	clearTimeout(timer);
	if (child?.pid) {
		try {
			process.kill(-child.pid, "SIGKILL");
		} catch {
			/* gone */
		}
	}
	server.closeAllConnections();
	await new Promise((done) => server.close(done));
	await rm(scratch, { recursive: true, force: true });
}
process.exit(exitCode);
