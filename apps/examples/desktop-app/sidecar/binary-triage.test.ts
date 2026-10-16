import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import lock from "../../../../scripts/binary-triage-tools.lock.json";
import { AnalysisWorkflowStore } from "./analysis-workflow-store";
import {
	BinaryTriageService,
	hashTriageFile,
	runTriageWorker,
	triageReport,
	verifyTriagePack,
} from "./binary-triage";
import { TriageRequest, triageEngine } from "./binary-triage-contracts";

const roots: string[] = [];
afterEach(async () => {
	vi.unstubAllEnvs();
	for (const root of roots.splice(0))
		await rm(root, { recursive: true, force: true });
});
async function pack() {
	const root = await mkdtemp(join(tmpdir(), "triage-owned-"));
	roots.push(root);
	const names = [
		"tools.lock.json",
		"triage.yar",
		"owned-fixture.exe",
		...lock.tools.map((t) => `${t.id}/${t.executable}`),
	];
	const files: Record<string, string> = {};
	for (const name of names) {
		const path = join(root, name);
		await mkdir(dirname(path), { recursive: true });
		await writeFile(
			path,
			name === "tools.lock.json" ? JSON.stringify(lock) : "owned fixture",
		);
		files[name] = await hashTriageFile(path);
	}
	await writeFile(
		join(root, "manifest.json"),
		JSON.stringify({ schemaVersion: 1, files }),
	);
	return root;
}
describe("fixed binary triage contracts", () => {
	it("rejects arbitrary commands, unknown options and unsafe selectors", () => {
		const input = {
			operation: "inspect_binary",
			target: "owned.exe",
			question: "What is it?",
		};
		expect(TriageRequest.parse(input).operation).toBe("inspect_binary");
		for (const v of [
			{ ...input, command: "!whoami" },
			{ ...input, operation: "debug" },
			{ ...input, target: "a\0b" },
			{ ...input, address: "0x1;!whoami" },
			{ ...input, operation: "find_references" },
		])
			expect(TriageRequest.safeParse(v).success).toBe(false);
		expect(
			TriageRequest.safeParse({
				...input,
				operation: "find_references",
				address: "0x1234",
			}).success,
		).toBe(true);
		expect(triageEngine("extract_strings")).toBe("floss");
	});
	it("verifies pinned inventory and rejects tampering, unknown files and traversal", async () => {
		const root = await pack();
		expect((await verifyTriagePack(root)).ruleHash).toMatch(/^[a-f0-9]{64}$/);
		await writeFile(join(root, "extra.dll"), "untrusted");
		await expect(verifyTriagePack(root)).rejects.toThrow("Untracked");
		await rm(join(root, "extra.dll"));
		await writeFile(join(root, "triage.yar"), "changed");
		await expect(verifyTriagePack(root)).rejects.toThrow("integrity");
		const m = JSON.parse(await readFile(join(root, "manifest.json"), "utf8"));
		m.files["../escape"] = "a".repeat(64);
		delete m.files["triage.yar"];
		await writeFile(join(root, "manifest.json"), JSON.stringify(m));
		await expect(verifyTriagePack(root)).rejects.toThrow("Unsafe");
	});
	it("keeps receipts session scoped and terminally immutable", async () => {
		const root = await pack(),
			store = new AnalysisWorkflowStore(join(root, "history.sqlite")),
			scope = { sessionId: "owner", workspace: root };
		try {
			const item = store.put(scope, "triage", {
				status: "running",
				targetSha256: "a".repeat(64),
			});
			expect(() =>
				store.get({ ...scope, sessionId: "other" }, item.id, "triage"),
			).toThrow("unavailable");
			const saved = store.completeTriage(scope, item.id, { status: "failed" });
			expect(() =>
				store.completeTriage(scope, item.id, { status: "completed" }),
			).toThrow("immutable");
			expect(triageReport(saved).unanswered).toContain(
				"No completed analysis evidence",
			);
		} finally {
			store.close();
		}
	});
	it("does not start a pre-cancelled process", async () => {
		const c = new AbortController();
		c.abort();
		expect(await runTriageWorker("missing-python", {}, ".", c.signal)).toEqual({
			status: "cancelled",
		});
	});
	it("never fabricates success for a missing interpreter", async () => {
		expect(
			(
				await runTriageWorker(
					join(tmpdir(), "missing-cline-owned-python"),
					{},
					".",
				)
			).status,
		).toBe("failed");
	});
	it("reserves readiness capacity before awaits and retains unresolved termination", async () => {
		const root = await pack();
		vi.stubEnv("CLINE_RE_PYTHON", process.execPath);
		const service = new BinaryTriageService(root, async () => ({
			status: "termination-unconfirmed",
		}));
		const first = service.test();
		await expect(service.test()).rejects.toThrow("active triage");
		await expect(first).rejects.toThrow("not ready");
		await expect(service.test()).rejects.toThrow("active triage");
	});
	it("records a completed bounded result without replay and confines target selection", async () => {
		const root = await pack(),
			workspace = await mkdtemp(join(tmpdir(), "triage-workspace-"));
		roots.push(workspace);
		vi.stubEnv("CLINE_RE_PYTHON", process.execPath);
		vi.stubEnv("CLINE_DIR", join(workspace, "private"));
		await writeFile(
			join(workspace, "owned.exe"),
			"MZCLINE_OWNED_TRIAGE_FIXTURE_V1",
		);
		const worker = vi.fn(async () => ({
			status: "completed" as const,
			output: {
				engine: "yara",
				version: "4.5.4",
				format: "pe",
				category: "rule-match",
				data: [{ rule: "cline_owned_fixture" }],
				coverage: "Owned neutral rules only",
			},
		}));
		const service = new BinaryTriageService(root, worker),
			store = new AnalysisWorkflowStore(join(workspace, "history.sqlite"));
		const scope = { sessionId: "owned", workspace },
			input = {
				operation: "scan_yara",
				target: "owned.exe",
				question: "What matches?",
			};
		try {
			const id = "11111111-1111-4111-8111-111111111111";
			const result = await service.run(scope, input, store, id);
			expect(result.status).toBe("completed");
			expect(result.resultHash).toMatch(/^[a-f0-9]{64}$/);
			await expect(service.run(scope, input, store, id)).rejects.toThrow();
			await expect(
				service.run(
					scope,
					{ ...input, target: "../outside.exe" },
					store,
					"22222222-2222-4222-8222-222222222222",
				),
			).rejects.toThrow();
			expect(worker).toHaveBeenCalledTimes(1);
		} finally {
			store.close();
		}
	});
});
