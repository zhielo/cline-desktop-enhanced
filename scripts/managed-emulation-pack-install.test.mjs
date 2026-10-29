// Real filesystem/selection/transaction tests only, not emulator/Hyper-V tests.
import { test } from "node:test";
import { writeFileSync } from "node:fs";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
	mkdtemp,
	mkdir,
	readFile,
	writeFile,
	readdir,
	rm,
	symlink,
	link,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
	createManagedEmulationPack,
	EMULATION_ENGINES,
	selectEmulationEngines,
} from "../apps/examples/desktop-app/sidecar/managed-emulation-pack.mjs";
const members = [
	"guest.iso",
	"image-manifest.json",
	"NOTICES.txt",
	"corresponding-source.tar.zst",
];
async function fixture(t) {
	const root = await mkdtemp(join(tmpdir(), "cline-pack-owned-"));
	t.after(() => rm(root, { recursive: true, force: true }));
	const sourceRoot = join(root, "source"),
		installRoot = join(root, "installed");
	await mkdir(sourceRoot);
	const catalog = { schemaVersion: 1, releaseId: "a".repeat(40), engines: {} };
	for (const id of EMULATION_ENGINES) {
		await mkdir(join(sourceRoot, id));
		catalog.engines[id] = {};
		for (const member of members) {
			const bytes = Buffer.from(
				`owned file-copy fixture, not a guest image: ${id}/${member}\n`,
			);
			await writeFile(join(sourceRoot, id, member), bytes);
			catalog.engines[id][member] = {
				bytes: bytes.length,
				sha256: createHash("sha256").update(bytes).digest("hex"),
			};
		}
	}
	return {
		root,
		sourceRoot,
		installRoot,
		catalog,
		pack: createManagedEmulationPack({ sourceRoot, installRoot, catalog }),
	};
}
test("default Install copies all four and verification never promotes activation or readiness", async (t) => {
	const f = await fixture(t);
	assert.equal(
		(await f.pack.status()).engines.every((e) => e.status === "not-installed"),
		true,
	);
	assert.deepEqual((await f.pack.install()).installed, EMULATION_ENGINES);
	assert.deepEqual((await f.pack.verify()).verified, EMULATION_ENGINES);
	const status = await f.pack.status();
	assert.equal(status.activation, "not-implemented");
	assert.equal(status.engineReadiness, "not-tested");
	assert.equal(
		status.engines.every((e) => e.status === "installed-unverified"),
		true,
	);
});
test("individual installs preserve earlier engine selections and immutable files", async (t) => {
	const f = await fixture(t);
	assert.deepEqual((await f.pack.install(["rnidbg", "qiling"])).installed, [
		"qiling",
		"rnidbg",
	]);
	const before = JSON.parse(
		await readFile(join(f.installRoot, "active.json"), "utf8"),
	);
	await f.pack.install(["unidbg"]);
	const after = JSON.parse(
		await readFile(join(f.installRoot, "active.json"), "utf8"),
	);
	assert.deepEqual(after.engines.qiling, before.engines.qiling);
	assert.deepEqual(after.engines.rnidbg, before.engines.rnidbg);
	assert.equal(Object.hasOwn(after.engines, "speakeasy"), false);
	assert.deepEqual(
		(await f.pack.verify(["qiling", "unidbg", "rnidbg"])).verified,
		["qiling", "unidbg", "rnidbg"],
	);
});
test("unknown, duplicate, empty and caller-shaped engine selections are refused", () => {
	for (const value of [
		[],
		["qiling", "qiling"],
		["unicorn"],
		["../qiling"],
		"all",
		null,
		{ engines: ["qiling"] },
	])
		assert.throws(() => selectEmulationEngines(value), /supported emulation/);
});
test("missing reviewed catalog never creates installation state", async (t) => {
	const f = await fixture(t);
	const pack = createManagedEmulationPack({ ...f, catalog: null });
	assert.equal((await pack.status()).available, false);
	await assert.rejects(pack.install(), /no reviewed bundled/);
	await assert.rejects(readFile(join(f.installRoot, "active.json")), {
		code: "ENOENT",
	});
});
test("checksum failure retains staging but never replaces a previous selection", async (t) => {
	const f = await fixture(t);
	await f.pack.install(["qiling"]);
	const before = await readFile(join(f.installRoot, "active.json"));
	const path = join(f.sourceRoot, "unidbg", "guest.iso");
	const bytes = await readFile(path);
	bytes[0] ^= 1;
	await writeFile(path, bytes);
	await assert.rejects(f.pack.install(["unidbg"]), /integrity mismatch/);
	assert.deepEqual(await readFile(join(f.installRoot, "active.json")), before);
	assert.equal((await readdir(join(f.installRoot, "staging"))).length, 1);
	await assert.rejects(readFile(join(f.installRoot, "install.lock")), {
		code: "ENOENT",
	});
});
test("cancellation before commit retains old selections and never installs a subset as complete", async (t) => {
	const f = await fixture(t);
	await f.pack.install(["qiling"]);
	const before = await readFile(join(f.installRoot, "active.json"));
	const controller = new AbortController();
	await assert.rejects(
		f.pack.install(["unidbg", "rnidbg"], {
			signal: controller.signal,
			phase: (phase) => {
				if (phase.startsWith("Installing rnidbg")) controller.abort();
			},
		}),
		{ name: "AbortError" },
	);
	assert.deepEqual(await readFile(join(f.installRoot, "active.json")), before);
	assert.equal((await readdir(join(f.installRoot, "staging"))).length, 1);
});
test("cancellation before admission starts no installation", async (t) => {
	const f = await fixture(t),
		controller = new AbortController();
	controller.abort();
	await assert.rejects(
		f.pack.install(undefined, { signal: controller.signal }),
		{ name: "AbortError" },
	);
	await assert.rejects(readdir(f.installRoot), { code: "ENOENT" });
});
test("untracked members and hard-linked inputs cannot be installed", async (t) => {
	const f = await fixture(t);
	await writeFile(join(f.sourceRoot, "qiling", "unexpected"), "extra");
	await assert.rejects(f.pack.install(["qiling"]), /untracked/);
	await rm(join(f.sourceRoot, "qiling", "unexpected"));
	await link(
		join(f.sourceRoot, "qiling", "guest.iso"),
		join(f.root, "linked-image"),
	);
	await assert.rejects(f.pack.install(["qiling"]), /Non-linked/);
});
test("linked source directories are refused before copying", {
	skip: process.platform === "win32",
}, async (t) => {
	const f = await fixture(t);
	await rm(join(f.sourceRoot, "qiling"), { recursive: true });
	await symlink(
		join(f.sourceRoot, "unidbg"),
		join(f.sourceRoot, "qiling"),
		"dir",
	);
	await assert.rejects(f.pack.install(["qiling"]), /Linked managed/);
});
test("a second installation cannot replace a held lease or join a different selection", async (t) => {
	const f = await fixture(t);
	let competing;
	await f.pack.install(["qiling"], {
		phase: () => {
			if (!competing)
				competing = assert.rejects(
					f.pack.install(["unidbg"]),
					/active or requires/,
				);
		},
	});
	await competing;
	assert.deepEqual(
		Object.keys(
			JSON.parse(await readFile(join(f.installRoot, "active.json"), "utf8"))
				.engines,
		),
		["qiling"],
	);
});
test("tampered installed bytes fail explicit verification without a readiness receipt", async (t) => {
	const f = await fixture(t);
	await f.pack.install(["qiling"]);
	const active = JSON.parse(
		await readFile(join(f.installRoot, "active.json"), "utf8"),
	);
	await writeFile(
		join(
			f.installRoot,
			"releases",
			active.engines.qiling.directory,
			"qiling",
			"guest.iso",
		),
		"tampered",
	);
	await assert.rejects(f.pack.verify(["qiling"]), /size mismatch/);
	assert.equal((await f.pack.status()).engineReadiness, "not-tested");
});
test("mutating the caller catalog cannot change captured integrity pins", async (t) => {
	const f = await fixture(t);
	f.catalog.engines.qiling["guest.iso"].sha256 = "0".repeat(64);
	await f.pack.install(["qiling"]);
	await f.pack.verify(["qiling"]);
});
test("pointer traversal fails closed", async (t) => {
	const f = await fixture(t);
	await f.pack.install(["qiling"]);
	const path = join(f.installRoot, "active.json");
	await writeFile(
		path,
		JSON.stringify({
			schemaVersion: 1,
			engines: {
				qiling: { catalogSha256: "a".repeat(64), directory: "../foreign" },
			},
		}),
	);
	await assert.rejects(f.pack.install(["unidbg"]), /installation reference/);
});
test("retained installation exhaustion refuses new copies without deleting old state", async (t) => {
	const f = await fixture(t);
	await f.pack.install(["qiling"]);
	const before = await readFile(join(f.installRoot, "active.json"));
	for (let i = 0; i < 7; i++)
		await mkdir(
			join(f.installRoot, "staging", `00000000-0000-4000-8000-00000000000${i}`),
		);
	await assert.rejects(
		f.pack.install(["unidbg"]),
		/Retained pack installation budget/,
	);
	assert.deepEqual(await readFile(join(f.installRoot, "active.json")), before);
	assert.equal((await readdir(join(f.installRoot, "staging"))).length, 7);
});
test("catalog shape and total size limits are checked before any allocation or copy", async (t) => {
	const f = await fixture(t);
	const large = structuredClone(f.catalog);
	for (const engine of EMULATION_ENGINES) {
		large.engines[engine]["guest.iso"].bytes = 768 * 1024 ** 2;
		large.engines[engine]["corresponding-source.tar.zst"].bytes =
			1536 * 1024 ** 2;
	}
	assert.throws(
		() => createManagedEmulationPack({ ...f, catalog: large }),
		/total byte budget/,
	);
	const extra = structuredClone(f.catalog);
	extra.engines.qiling.command = "DO NOT EXECUTE";
	assert.throws(
		() => createManagedEmulationPack({ ...f, catalog: extra }),
		/Invalid managed pack record/,
	);
});
test("nested source and destination roots are refused on the native path platform", async (t) => {
	const f = await fixture(t);
	assert.throws(
		() =>
			createManagedEmulationPack({
				...f,
				installRoot: join(f.sourceRoot, "nested"),
			}),
		/Separate fixed/,
	);
	assert.throws(
		() => createManagedEmulationPack({ ...f, sourceRoot: f.installRoot }),
		/Separate fixed/,
	);
});
test("repeat Install rehashes and reuses all four without new releases or pointer writes", async (t) => {
	const f = await fixture(t);
	await f.pack.install();
	const before = await readFile(join(f.installRoot, "active.json"));
	const result = await f.pack.install();
	assert.deepEqual(result.reused, EMULATION_ENGINES);
	assert.deepEqual(await readFile(join(f.installRoot, "active.json")), before);
	assert.equal((await readdir(join(f.installRoot, "releases"))).length, 1);
	assert.equal((await readdir(join(f.installRoot, "staging"))).length, 0);
});
test("mixed selection copies only missing engines and preserves reused directory", async (t) => {
	const f = await fixture(t);
	await f.pack.install(["qiling"]);
	const before = JSON.parse(
		await readFile(join(f.installRoot, "active.json"), "utf8"),
	);
	const result = await f.pack.install(["qiling", "unidbg"]);
	const after = JSON.parse(
		await readFile(join(f.installRoot, "active.json"), "utf8"),
	);
	assert.deepEqual(result.reused, ["qiling"]);
	assert.deepEqual(after.engines.qiling, before.engines.qiling);
	assert.notEqual(
		after.engines.qiling.directory,
		after.engines.unidbg.directory,
	);
	assert.deepEqual(
		await readdir(
			join(f.installRoot, "releases", after.engines.unidbg.directory),
		),
		["unidbg"],
	);
});
test("corrupt installed bytes get a fresh verified copy without deleting previous evidence", async (t) => {
	const f = await fixture(t);
	await f.pack.install(["qiling"]);
	const before = JSON.parse(
		await readFile(join(f.installRoot, "active.json"), "utf8"),
	);
	const oldFile = join(
		f.installRoot,
		"releases",
		before.engines.qiling.directory,
		"qiling",
		"guest.iso",
	);
	await writeFile(oldFile, "corrupt");
	const result = await f.pack.install(["qiling"]);
	assert.deepEqual(result.reused, []);
	assert.equal(await readFile(oldFile, "utf8"), "corrupt");
	const after = JSON.parse(
		await readFile(join(f.installRoot, "active.json"), "utf8"),
	);
	assert.notEqual(
		after.engines.qiling.directory,
		before.engines.qiling.directory,
	);
	assert.deepEqual((await f.pack.verify(["qiling"])).verified, ["qiling"]);
});
test("verified reuse works without source media and at retained transaction capacity", async (t) => {
	const f = await fixture(t);
	await f.pack.install();
	await rm(f.sourceRoot, { recursive: true });
	for (let i = 0; i < 7; i++)
		await mkdir(
			join(
				f.installRoot,
				"staging",
				`11111111-1111-4111-8111-${String(i).padStart(12, "0")}`,
			),
		);
	assert.deepEqual((await f.pack.install()).reused, EMULATION_ENGINES);
	assert.equal((await readdir(join(f.installRoot, "releases"))).length, 1);
});
test("cancellation during reuse is not swallowed as repair or active-pointer publication", async (t) => {
	const f = await fixture(t);
	await f.pack.install(["qiling"]);
	const before = await readFile(join(f.installRoot, "active.json"));
	const controller = new AbortController();
	await assert.rejects(
		f.pack.install(["qiling"], {
			signal: controller.signal,
			phase: () => controller.abort(),
		}),
		{ name: "AbortError" },
	);
	assert.deepEqual(await readFile(join(f.installRoot, "active.json")), before);
	assert.equal((await readdir(join(f.installRoot, "releases"))).length, 1);
	assert.deepEqual((await f.pack.install(["qiling"])).reused, ["qiling"]);
});
test("changed active pointer during reuse refuses a false successful receipt", async (t) => {
	const f = await fixture(t);
	await f.pack.install(["qiling"]);

	await assert.rejects(
		f.pack.install(["qiling"], {
			phase: () => {
				writeFileSync(
					join(f.installRoot, "active.json"),
					JSON.stringify({ schemaVersion: 1, engines: {} }),
				);
			},
		}),
		/selection changed/,
	);
});
