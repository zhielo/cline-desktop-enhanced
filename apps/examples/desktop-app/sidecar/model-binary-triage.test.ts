import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import lock from "../../../../scripts/binary-triage-tools.lock.json";
import { AnalysisWorkflowStore } from "./analysis-workflow-store";
import {
	BinaryTriageService,
	hashTriageFile,
	triageEvidencePage,
} from "./binary-triage";
import { triageEngine } from "./binary-triage-contracts";
import {
	type ModelTriagePorts,
	runModelBinaryTriage,
} from "./model-binary-triage";

const roots: string[] = [];
const stores: AnalysisWorkflowStore[] = [];
afterEach(async () => {
	for (const store of stores.splice(0)) store.close();
	vi.unstubAllEnvs();
	for (const root of roots.splice(0))
		await rm(root, { recursive: true, force: true });
});
async function fixture() {
	const root = await mkdtemp(join(tmpdir(), "model-triage-"));
	roots.push(root);
	const pack = join(root, "pack"),
		workspace = join(root, "workspace");
	await mkdir(workspace);
	const files: Record<string, string> = {};
	for (const name of [
		"tools.lock.json",
		"triage.yar",
		"owned-fixture.exe",
		...lock.tools.map((t) => `${t.id}/${t.executable}`),
	]) {
		const file = join(pack, name);
		await mkdir(dirname(file), { recursive: true });
		await writeFile(
			file,
			name === "tools.lock.json" ? JSON.stringify(lock) : "owned",
		);
		files[name] = await hashTriageFile(file);
	}
	await writeFile(
		join(pack, "manifest.json"),
		JSON.stringify({ schemaVersion: 1, files }),
	);
	await writeFile(
		join(workspace, "owned.exe"),
		"MZCLINE_OWNED_TRIAGE_FIXTURE_V1",
	);
	// This suite injects its worker; hash a small owned interpreter identity.
	// Hashing the 100+ MiB Node executable on every transaction needlessly
	// turns seven mocked operations into gigabytes of I/O under CI contention.
	const python = join(root, "owned-mock-python");
	await writeFile(python, "owned mock interpreter identity; never executed");
	vi.stubEnv("CLINE_RE_PYTHON", python);
	vi.stubEnv("CLINE_DIR", join(root, "private"));
	const worker = vi.fn(
		async (
			_python: string,
			args: Record<string, unknown>,
			_cwd: string,
			_signal?: AbortSignal,
		) => ({
			status: "completed" as const,
			output: {
				engine: triageEngine(args.operation as never),
				version:
					args.operation === "scan_yara"
						? "4.5.4"
						: args.operation === "identify_capabilities"
							? "9.4.0"
							: args.operation === "extract_strings"
								? "v3.1.1-0-g3cd3ee6"
								: "6.2.4",
				format: "pe",
				category: "derived",
				data: [
					{
						rule: "cline_owned_fixture",
						text: "CLINE_OWNED_TRIAGE_FIXTURE_V1",
					},
				],
				coverage: "owned mock fixture only",
			},
		}),
	);
	const service = new BinaryTriageService(pack, worker);
	await service.test();
	worker.mockClear();
	const store = new AnalysisWorkflowStore(join(root, "history.sqlite"));
	stores.push(store);
	const ports: ModelTriagePorts = {
		service,
		store,
		scope: { sessionId: "owner", workspace },
		assertCurrent: vi.fn(),
		review: vi.fn(async () => true),
	};
	return { ports, worker, root, workspace, pack };
}
function call(operation = "inspect_binary") {
	return {
		operation: "advanced_analysis",
		advanced_action: "binary_triage",
		target: "owned.exe",
		advanced_options: {
			binary_triage: {
				action: "run",
				operation,
				question: "What evidence is available?",
				...(["get_function_disassembly", "find_references"].includes(operation)
					? { address: "0x140001000" }
					: {}),
			},
		},
	};
}
const read = (id: string, offset = 0) => ({
	operation: "advanced_analysis",
	advanced_action: "binary_triage",
	advanced_options: {
		binary_triage: { action: "read", receipt_id: id, offset, limit: 32 },
	},
});
describe("host-owned model binary triage", () => {
	it("routes all seven operations through shared service and returns bounded saved evidence", async () => {
		const { ports, worker } = await fixture();
		for (const operation of [
			"inspect_binary",
			"list_functions",
			"get_function_disassembly",
			"find_references",
			"scan_yara",
			"identify_capabilities",
			"extract_strings",
		]) {
			const result = JSON.parse(
				await runModelBinaryTriage(call(operation), ports),
			);
			expect(result.status).toBe("completed");
			expect(result.targetSha256).toMatch(/^[a-f0-9]{64}$/);
			expect(result.observedTargetExecution).toBe(false);
			expect(result.text.length).toBeLessThanOrEqual(4096);
			const page = JSON.parse(
				await runModelBinaryTriage(read(result.receiptId), ports),
			);
			expect(page.hasMore).toBe(true);
			expect(page.text).toHaveLength(32);
		}
		expect(worker).toHaveBeenCalledTimes(7);
		expect(ports.review).toHaveBeenCalledTimes(7);
	});
	it("denial and pre-cancellation never execute engines", async () => {
		const { ports, worker } = await fixture();
		ports.review = vi.fn(async () => false);
		await expect(runModelBinaryTriage(call(), ports)).rejects.toThrow("denied");
		const c = new AbortController();
		c.abort();
		ports.signal = c.signal;
		await expect(runModelBinaryTriage(call(), ports)).rejects.toThrow();
		expect(worker).not.toHaveBeenCalled();
	});
	it("changed input after review invalidates approval", async () => {
		const { ports, worker, workspace } = await fixture();
		ports.review = async () => {
			await writeFile(join(workspace, "owned.exe"), "MZ changed");
			return true;
		};
		await expect(runModelBinaryTriage(call(), ports)).rejects.toThrow(
			"identity changed",
		);
		expect(worker).not.toHaveBeenCalled();
	});
	it("changed interpreter bytes invalidate readiness after review without executing", async () => {
		const { ports, worker } = await fixture();
		ports.review = async () => {
			await writeFile(process.env.CLINE_RE_PYTHON!, "changed mock interpreter");
			return true;
		};
		await expect(runModelBinaryTriage(call(), ports)).rejects.toThrow(
			"matching owned-fixture test",
		);
		expect(worker).not.toHaveBeenCalled();
	});
	it("mode/profile/scope changes after review cannot start execution", async () => {
		const { ports, worker } = await fixture();
		let valid = true;
		ports.assertCurrent = () => {
			if (!valid) throw new Error("scope changed");
		};
		ports.review = async () => {
			valid = false;
			return true;
		};
		await expect(runModelBinaryTriage(call(), ports)).rejects.toThrow(
			"scope changed",
		);
		expect(worker).not.toHaveBeenCalled();
	});
	it("target escape and malformed request cannot reach review or worker", async () => {
		const { ports, worker } = await fixture();
		await expect(
			runModelBinaryTriage(
				{ ...call(), target: "../pack/owned-fixture.exe" },
				ports,
			),
		).rejects.toThrow("confined");
		await expect(
			runModelBinaryTriage({ ...call(), confirmed: true }, ports),
		).rejects.toThrow();
		expect(ports.review).not.toHaveBeenCalled();
		expect(worker).not.toHaveBeenCalled();
	});
	it("saved reads remain non-executing and scoped; status does not run self-tests", async () => {
		const { ports, worker } = await fixture();
		const result = JSON.parse(await runModelBinaryTriage(call(), ports));
		worker.mockClear();
		ports.assertCurrent = (execution) => {
			if (execution) throw new Error("Analysis Off");
		};
		expect(
			JSON.parse(await runModelBinaryTriage(read(result.receiptId), ports))
				.receiptId,
		).toBe(result.receiptId);
		await runModelBinaryTriage(
			{
				operation: "advanced_analysis",
				advanced_action: "binary_triage",
				advanced_options: { binary_triage: { action: "status" } },
			},
			ports,
		);
		await expect(
			runModelBinaryTriage(read(result.receiptId), {
				...ports,
				scope: { ...ports.scope, sessionId: "other" },
			}),
		).rejects.toThrow("unavailable");
		expect(worker).not.toHaveBeenCalled();
		expect(() => triageEvidencePage({}, 0, 4097)).toThrow();
	});
	it("task cancellation reaches the child and retains cancelled, not completed evidence", async () => {
		const { ports, worker } = await fixture();
		const c = new AbortController();
		ports.signal = c.signal;
		worker.mockImplementationOnce(
			async (_p, _a, _d, signal) =>
				new Promise((resolve) => {
					signal!.addEventListener(
						"abort",
						() => resolve({ status: "cancelled" } as never),
						{ once: true },
					);
					c.abort();
				}),
		);
		const result = JSON.parse(await runModelBinaryTriage(call(), ports));
		expect(result.status).toBe("cancelled");
		expect(result.text).toBe("null");
	});
	it("termination-unconfirmed remains blocked even when scope changes", async () => {
		const { ports, worker } = await fixture();
		let valid = true;
		ports.assertCurrent = () => {
			if (!valid) throw new Error("scope changed");
		};
		worker.mockImplementationOnce(async () => {
			valid = false;
			return { status: "termination-unconfirmed" } as never;
		});
		await expect(runModelBinaryTriage(call(), ports)).rejects.toThrow(
			"scope changed",
		);
		const rows = ports.store.list(ports.scope, "triage");
		expect(rows[0].status).toBe("termination-unconfirmed");
	});
});
