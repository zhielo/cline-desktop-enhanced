import { randomUUID } from "node:crypto";
import {
	mkdir,
	mkdtemp,
	readdir,
	realpath,
	rm,
	writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, expect, it } from "vitest";
import {
	guardManagedBatchArguments,
	managedRootIsRunning,
	ManagedEnginePool,
} from "./managed-engine-pool";
import {
	MANAGED_GHIDRA_SCRIPT,
	managedIdaScript,
} from "./managed-engine-scripts";

const resources: { root: string; pool: ManagedEnginePool }[] = [];
afterEach(async () => {
	for (const x of resources.splice(0)) {
		await x.pool.close();
		expect(await readdir(join(x.root, "leases"))).toEqual([]);
		await rm(x.root, { recursive: true, force: true });
	}
});
async function fixture(
	options: { idleMs?: number; lifetimeMs?: number; maxWorkers?: number } = {},
) {
	const root = await realpath(
		await mkdtemp(join(tmpdir(), "managed-engine-owned-")),
	);
	await mkdir(join(root, "leases"));
	const pool = new ManagedEnginePool({
		leaseRoot: join(root, "leases"),
		...options,
	});
	resources.push({ root, pool });
	let launches = 0;
	const factory = async (mode = "ok") => {
		launches++;
		const box = await realpath(await mkdtemp(join(root, "box-"))),
			nonce = randomUUID(),
			program = join(box, "owned.mjs");
		await writeFile(
			program,
			`import fs from 'node:fs';import path from 'node:path';
const root=process.argv[2],nonce=process.argv[3],mode=process.argv[4];
function publish(name,data){fs.writeFileSync(path.join(root,name+'.stage'),JSON.stringify(data));fs.renameSync(path.join(root,name+'.stage'),path.join(root,name));}
publish('ready.json',{protocol:1,nonce:mode==='badready'?'bad':nonce});
setInterval(()=>{const file=path.join(root,'request.json');if(!fs.existsSync(file))return;const r=JSON.parse(fs.readFileSync(file,'utf8'));fs.unlinkSync(file);
if(mode==='hang'||Buffer.from(r.value64,'base64').toString('utf8')==='hang')return;if(mode==='crash')process.exit(7);
const response={protocol:1,nonce:mode==='badnonce'?'wrong':nonce,id:mode==='badid'?'wrong':r.id,status:'completed',entry:'0x10',code:JSON.stringify(Buffer.from(r.value64,'base64').toString('utf8'))};
if(mode==='oversize')response.code='x'.repeat(1024*1024);if(mode==='failed'){response.status='failed';response.error='Ambiguous exact function name';}
publish(r.id+'.json',response);
},20);`,
		);
		return {
			root: box,
			command: process.execPath,
			args: [program, box, nonce, mode],
			nonce,
		};
	};
	return { root, pool, factory, launches: () => launches };
}
it("reuses one owned live process for distinct exact selectors while retaining its lease", async () => {
	const f = await fixture(),
		project = join(f.root, "project");
	const first = await f.pool.query(
		"identity",
		project,
		() => f.factory(),
		{ address: "0x10" },
		undefined,
		5000,
	);
	const second = await f.pool.query(
		"identity",
		project,
		() => f.factory(),
		{ symbol: 'x"; import os; #' },
		undefined,
		5000,
	);
	expect(second.workerId).toBe(first.workerId);
	expect(second.pid).toBe(first.pid);
	expect(second.reusedWorker).toBe(true);
	expect(f.launches()).toBe(1);
	expect(JSON.parse(second.code)).toBe('x"; import os; #');
	expect((await readdir(join(f.root, "leases"))).length).toBe(1);
});
it("bounds pool capacity and never silently evicts another live worker", async () => {
	const f = await fixture({ maxWorkers: 2 });
	await f.pool.query(
		"one",
		join(f.root, "one"),
		() => f.factory(),
		{ address: "0x10" },
		undefined,
		5000,
	);
	await f.pool.query(
		"two",
		join(f.root, "two"),
		() => f.factory(),
		{ address: "0x10" },
		undefined,
		5000,
	);
	await expect(
		f.pool.query(
			"three",
			join(f.root, "three"),
			() => f.factory(),
			{ address: "0x10" },
			undefined,
			5000,
		),
	).rejects.toThrow("capacity reached");
	expect(f.launches()).toBe(2);
});
it("rejects invalid selectors before spawning", async () => {
	const f = await fixture();
	await expect(
		f.pool.query("x", f.root, () => f.factory(), { address: "nothex" }),
	).rejects.toThrow("exact function selector");
	expect(f.launches()).toBe(0);
});
it.each([
	"badready",
	"badnonce",
	"badid",
	"oversize",
	"failed",
	"crash",
])("fails closed for %s without automatic restart", async (mode) => {
	const f = await fixture();
	await expect(
		f.pool.query(
			"x",
			f.root,
			() => f.factory(mode),
			{ address: "0x10" },
			undefined,
			5000,
		),
	).rejects.toThrow();
	expect(f.launches()).toBe(1);
	expect(await readdir(join(f.root, "leases"))).toEqual([]);
});
it("cancels an in-flight request, rejects concurrent use and releases only after actual exit", async () => {
	const f = await fixture(),
		signal = new AbortController();
	const query = f.pool.query(
		"x",
		f.root,
		() => f.factory("hang"),
		{ address: "0x10" },
		signal.signal,
		5000,
	);
	const rejection = expect(query).rejects.toThrow();
	while (f.launches() === 0) await new Promise((r) => setTimeout(r, 10));
	await expect(
		f.pool.query(
			"x",
			f.root,
			() => f.factory(),
			{ address: "0x20" },
			undefined,
			5000,
		),
	).rejects.toThrow(/busy|startup/);
	signal.abort();
	await rejection;
	expect(f.launches()).toBe(1);
	expect(await readdir(join(f.root, "leases"))).toEqual([]);
});
it("terminates idle owned workers and releases project coordination", async () => {
	const f = await fixture({ idleMs: 60 });
	await f.pool.query(
		"x",
		f.root,
		() => f.factory(),
		{ address: "0x10" },
		undefined,
		5000,
	);
	const until = Date.now() + 8000;
	while ((await readdir(join(f.root, "leases"))).length && Date.now() < until)
		await new Promise((r) => setTimeout(r, 30));
	expect(await readdir(join(f.root, "leases"))).toEqual([]);
	expect(f.launches()).toBe(1);
});
it("fixed adapters keep requests data-only and prohibit nearby/ambiguous fallback", () => {
	expect(MANAGED_GHIDRA_SCRIPT).toContain("getFunctionAt");
	expect(MANAGED_GHIDRA_SCRIPT).toContain("Ambiguous exact function name");
	expect(MANAGED_GHIDRA_SCRIPT).toContain("code.length()>100000");
	const ida = managedIdaScript('C:\\owned\\root"; #', "owned-nonce");
	expect(
		JSON.parse(
			ida
				.split("\n")
				.find((x) => x.startsWith("ROOT="))!
				.slice(5),
		),
	).toBe('C:\\owned\\root"; #');
	expect(ida).toContain("f.start_ea==address");
	expect(ida).toContain("finally: idc.qexit(0)");
	expect(ida).not.toContain("eval(");
	expect(ida).not.toContain("exec(");
});

it("times out a blocked reused request without replaying and terminates its owned process", async () => {
	const f = await fixture();
	await f.pool.query(
		"x",
		f.root,
		() => f.factory(),
		{ address: "0x10" },
		undefined,
		5000,
	);
	await expect(
		f.pool.query(
			"x",
			f.root,
			() => f.factory(),
			{ symbol: "hang" },
			undefined,
			100,
		),
	).rejects.toThrow("response timed out");
	expect(f.launches()).toBe(1);
	expect(await readdir(join(f.root, "leases"))).toEqual([]);
});

it("rejects cmd.exe expansion/control characters without loosening ordinary spaced paths", () => {
	expect(() =>
		guardManagedBatchArguments("C:\\Tools Folder\\analyzeHeadless.bat", [
			"C:\\Owned Project",
			"-postScript",
			"ClineManagedSelected.java",
		]),
	).not.toThrow();
	for (const character of [
		"&",
		"|",
		"<",
		">",
		"^",
		"%",
		"!",
		"\n",
		"\r",
		'"',
	]) {
		expect(() =>
			guardManagedBatchArguments("C:\\engine.bat", [
				"owned" + character + "path",
			]),
		).toThrow("unsupported cmd.exe");
		expect(() =>
			guardManagedBatchArguments("C:\\engine" + character + ".bat", []),
		).toThrow("unsupported cmd.exe");
	}
});

it("never treats an already exited root PID as safe to terminate", () => {
	expect(
		managedRootIsRunning({ pid: 123, exitCode: null, signalCode: null }),
	).toBe(true);
	expect(
		managedRootIsRunning({ pid: 123, exitCode: 0, signalCode: null }),
	).toBe(false);
	expect(
		managedRootIsRunning({ pid: 123, exitCode: null, signalCode: "SIGKILL" }),
	).toBe(false);
	expect(
		managedRootIsRunning({ pid: undefined, exitCode: null, signalCode: null }),
	).toBe(false);
});

it("streams bounded owned mailbox states without changing single-request execution", async () => {
  const f=await fixture();const progress: {phase:string;pid:number|null}[]=[];
  const result=await f.pool.query("progress",join(f.root,"progress"),()=>f.factory(),{address:"0x10"},undefined,5000,event=>progress.push(event));
  expect(progress.some(event=>event.phase.includes("ready mailbox"))).toBe(true);
  expect(progress.some(event=>event.phase.includes("request submitted once") && event.pid===result.pid)).toBe(true);
  expect(progress.at(-1)?.phase).toBe("selected-function response verified");
  expect(f.launches()).toBe(1);
});
