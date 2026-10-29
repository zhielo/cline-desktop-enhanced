/**
 * Data-only Emulation Framework Pack installation.
 *
 * The catalog is supplied by compiled, reviewed application code, never by an
 * IPC request, a downloaded manifest, an environment variable or active.json.
 * Installed bytes are NOT permission to execute them or VM/engine readiness.
 */
import { constants } from "node:fs";
import {
	lstat,
	mkdir,
	open,
	readdir,
	rename,
	statfs,
	unlink,
} from "node:fs/promises";
import { createHash, randomUUID } from "node:crypto";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";

export const EMULATION_ENGINES = Object.freeze([
	"qiling",
	"unidbg",
	"rnidbg",
	"speakeasy",
]);
const MEMBERS = Object.freeze([
	"guest.iso",
	"image-manifest.json",
	"NOTICES.txt",
	"corresponding-source.tar.zst",
]);
const MAX_TOTAL = 8 * 1024 ** 3;
const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
const uuid =
	/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
function exactKeys(value, keys) {
	if (
		!value ||
		typeof value !== "object" ||
		Array.isArray(value) ||
		Object.keys(value).length !== keys.length ||
		keys.some((key) => !Object.hasOwn(value, key))
	)
		throw new Error("Invalid managed pack record");
}
export function selectEmulationEngines(selection) {
	if (
		!Array.isArray(selection) ||
		!selection.length ||
		selection.length > 4 ||
		[...selection].some((id) => !EMULATION_ENGINES.includes(id)) ||
		new Set(selection).size !== selection.length
	)
		throw new Error("Select one or more distinct supported emulation engines");
	// Stable order makes selecting all four identical to the default Install path.
	return EMULATION_ENGINES.filter((id) => selection.includes(id));
}
function catalogValue(input) {
	// A private deep copy prevents a caller mutating validated pins during I/O.
	const catalog = structuredClone(input);
	exactKeys(catalog, ["schemaVersion", "releaseId", "engines"]);
	if (catalog.schemaVersion !== 1 || !/^[a-f0-9]{40}$/.test(catalog.releaseId))
		throw new Error("Reviewed managed pack catalog required");
	exactKeys(catalog.engines, EMULATION_ENGINES);
	let total = 0;
	for (const id of EMULATION_ENGINES) {
		exactKeys(catalog.engines[id], MEMBERS);
		for (const member of MEMBERS) {
			const file = catalog.engines[id][member];
			exactKeys(file, ["bytes", "sha256"]);
			const limit =
				member === "guest.iso"
					? 768 * 1024 ** 2
					: member === "corresponding-source.tar.zst"
						? 1536 * 1024 ** 2
						: 1024 ** 2;
			if (
				!Number.isSafeInteger(file.bytes) ||
				file.bytes < 1 ||
				file.bytes > limit ||
				!/^[a-f0-9]{64}$/.test(file.sha256)
			)
				throw new Error("Managed pack inventory budget or digest");
			total += file.bytes;
		}
	}
	if (total > MAX_TOTAL) throw new Error("Managed pack total byte budget");
	return catalog;
}
async function directory(path, create = false) {
	if (!isAbsolute(path) || path !== resolve(path))
		throw new Error("Fixed absolute pack root required");
	const parent = dirname(path);
	if (parent !== path) await directory(parent, create);
	if (create) {
		try {
			await mkdir(path, { mode: 0o700 });
		} catch (error) {
			if (error.code !== "EEXIST") throw error;
		}
	}
	const info = await lstat(path);
	if (!info.isDirectory() || info.isSymbolicLink())
		throw new Error("Linked managed pack directory forbidden");
}
function regular(info) {
	if (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1)
		throw new Error("Non-linked single-owner pack file required");
}
function integrityError(message) {
	return Object.assign(new Error(message), {
		code: "ERR_MANAGED_PACK_INTEGRITY",
	});
}
function unchanged(before, after) {
	return (
		before.dev === after.dev &&
		before.ino === after.ino &&
		before.size === after.size &&
		before.mtimeMs === after.mtimeMs &&
		before.ctimeMs === after.ctimeMs
	);
}
async function transfer(source, destination, pin, signal) {
	signal?.throwIfAborted();
	const before = await lstat(source);
	regular(before);
	if (before.size !== pin.bytes)
		throw integrityError("Managed pack member size mismatch");
	const input = await open(
		source,
		constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0),
	);
	let output;
	try {
		const initial = await input.stat();
		regular(initial);
		if (!unchanged(before, initial))
			throw new Error("Managed pack source changed");
		if (destination) output = await open(destination, "wx", 0o600);
		const hash = createHash("sha256");
		const buffer = Buffer.allocUnsafe(65536);
		let total = 0;
		for (;;) {
			signal?.throwIfAborted();
			const { bytesRead } = await input.read(buffer, 0, buffer.length, null);
			if (!bytesRead) break;
			total += bytesRead;
			if (total > pin.bytes) throw new Error("Managed pack member grew");
			hash.update(buffer.subarray(0, bytesRead));
			if (output) {
				let offset = 0;
				while (offset < bytesRead) {
					signal?.throwIfAborted();
					const { bytesWritten } = await output.write(
						buffer,
						offset,
						bytesRead - offset,
					);
					if (!bytesWritten)
						throw new Error("Managed pack write made no progress");
					offset += bytesWritten;
				}
			}
		}
		if (
			total !== pin.bytes ||
			hash.digest("hex") !== pin.sha256 ||
			!unchanged(initial, await input.stat()) ||
			!unchanged(before, await lstat(source))
		)
			throw integrityError("Managed pack integrity mismatch");
		if (output) {
			await output.sync();
			// Verify bytes actually written, not just bytes read from the source.
			await output.close();
			output = undefined;
			await transfer(destination, undefined, pin, signal);
		}
	} finally {
		try {
			await output?.close();
		} finally {
			await input.close();
		}
	}
}
async function pointer(root) {
	const path = join(root, "active.json");
	let before;
	try {
		before = await lstat(path);
	} catch (error) {
		if (error.code === "ENOENT")
			return { bytes: undefined, value: { schemaVersion: 1, engines: {} } };
		throw error;
	}
	regular(before);
	if (before.size > 8192) throw new Error("Managed pack pointer budget");
	const handle = await open(
		path,
		constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0),
	);
	let bytes;
	try {
		if (!unchanged(before, await handle.stat()))
			throw new Error("Managed pack pointer changed");
		// Bounded read even if another process grows the open file.
		const buffer = Buffer.alloc(8193);
		let length = 0;
		while (length < buffer.length) {
			const { bytesRead } = await handle.read(
				buffer,
				length,
				buffer.length - length,
				length,
			);
			if (!bytesRead) break;
			length += bytesRead;
		}
		if (
			length !== before.size ||
			!unchanged(before, await handle.stat()) ||
			!unchanged(before, await lstat(path))
		)
			throw new Error("Managed pack pointer changed");
		bytes = buffer.subarray(0, length);
	} finally {
		await handle.close();
	}
	const value = JSON.parse(bytes.toString("utf8"));
	exactKeys(value, ["schemaVersion", "engines"]);
	if (
		value.schemaVersion !== 1 ||
		!value.engines ||
		typeof value.engines !== "object" ||
		Array.isArray(value.engines) ||
		Object.keys(value.engines).some((id) => !EMULATION_ENGINES.includes(id))
	)
		throw new Error("Invalid managed pack selection");
	for (const record of Object.values(value.engines)) {
		exactKeys(record, ["catalogSha256", "directory"]);
		if (
			!/^[a-f0-9]{64}$/.test(record.catalogSha256) ||
			!uuid.test(record.directory)
		)
			throw new Error("Invalid managed pack installation reference");
	}
	return { bytes, value };
}
async function releaseLease(lease, path, identity, operationError) {
	try {
		// Release only this invocation's lease. Never adopt or remove stale
		// leases, replay interrupted work or recursively clean retained files.
		await lease.close();
		const retained = await lstat(path);
		if (retained.dev !== identity.dev || retained.ino !== identity.ino)
			throw new Error(
				"Managed pack lease changed; retained state requires inspection",
			);
		await unlink(path);
	} catch (error) {
		if (operationError)
			throw new AggregateError(
				[operationError, error],
				"Managed pack operation and lease release both failed; inspect retained state",
			);
		throw error;
	}
}
function contains(parent, child) {
	const path = relative(parent, child);
	return (
		path === "" ||
		(!isAbsolute(path) && path !== ".." && !path.startsWith(`..${sep}`))
	);
}
/**
 * Trusted host construction only. No path/catalog option is accepted by the
 * public Setup Center command. This factory is also used by real-file tests.
 */
export function createManagedEmulationPack({
	sourceRoot,
	installRoot,
	catalog: supplied,
}) {
	if (
		![sourceRoot, installRoot].every(
			(path) => isAbsolute(path) && path === resolve(path),
		) ||
		contains(sourceRoot, installRoot) ||
		contains(installRoot, sourceRoot)
	)
		throw new Error("Separate fixed managed pack roots required");
	const catalog = supplied === null ? null : catalogValue(supplied);
	const catalogSha256 = catalog && digest(JSON.stringify(catalog));
	async function verifyEngine(id, record, signal, phase) {
		signal?.throwIfAborted();
		if (!record || record.catalogSha256 !== catalogSha256)
			throw integrityError(
				"Selected engine is absent or belongs to a different managed pack catalog",
			);
		const root = join(installRoot, "releases", record.directory, id);
		await directory(root);
		if (
			JSON.stringify((await readdir(root)).sort()) !==
			JSON.stringify([...MEMBERS].sort())
		)
			throw integrityError("Installed managed pack inventory mismatch");
		phase(`Verifying installed ${id} files; no engine is executed`);
		for (const member of MEMBERS)
			await transfer(
				join(root, member),
				undefined,
				catalog.engines[id][member],
				signal,
			);
	}
	async function status() {
		let selected = {};
		try {
			await directory(installRoot);
			selected = (await pointer(installRoot)).value.engines;
		} catch (error) {
			if (error.code !== "ENOENT") throw error;
		}
		return {
			available: catalog !== null,
			activation: "not-implemented",
			engineReadiness: "not-tested",
			engines: EMULATION_ENGINES.map((id) => ({
				id,
				status: !selected[id]
					? "not-installed"
					: selected[id].catalogSha256 === catalogSha256
						? "installed-unverified"
						: "stale",
			})),
		};
	}
	async function install(
		selection = EMULATION_ENGINES,
		{ signal, phase = () => {} } = {},
	) {
		const ids = selectEmulationEngines(selection);
		if (!catalog)
			throw new Error(
				"This build has no reviewed bundled Emulation Framework Pack",
			);
		signal?.throwIfAborted();
		await directory(installRoot, true);
		const leasePath = join(installRoot, "install.lock");
		const lease = await open(leasePath, "wx", 0o600).catch((error) => {
			throw new Error(
				error.code === "EEXIST"
					? "Emulation pack installation is active or requires interrupted-job inspection"
					: "Unable to acquire managed pack installation lease",
			);
		});
		const leaseIdentity = await lease.stat();
		const transaction = randomUUID();
		let operationError;
		try {
			await lease.writeFile(JSON.stringify({ transaction }));
			await lease.sync();
			const previous = await pointer(installRoot);
			const reused = [];
			const needed = [];
			for (const id of ids) {
				try {
					await verifyEngine(id, previous.value.engines[id], signal, phase);
					reused.push(id);
				} catch (error) {
					// Cancellation and unsafe links/access errors must never become repair.
					signal?.throwIfAborted();
					if (
						error.code !== "ERR_MANAGED_PACK_INTEGRITY" &&
						error.code !== "ENOENT"
					)
						throw error;
					needed.push(id);
				}
			}
			signal?.throwIfAborted();
			if (!needed.length) {
				if (
					(await pointer(installRoot)).bytes?.toString("hex") !==
					previous.bytes?.toString("hex")
				)
					throw new Error(
						"Managed pack selection changed during reuse verification",
					);
				return {
					installed: ids,
					reused,
					catalogSha256,
					activation: "not-implemented",
					engineReadiness: "not-tested",
				};
			}
			await directory(sourceRoot);
			const staging = join(installRoot, "staging");
			const releases = join(installRoot, "releases");
			await directory(staging, true);
			await directory(releases, true);
			const retained = [
				...(await readdir(staging)),
				...(await readdir(releases)),
			];
			if (retained.length >= 8 || retained.some((entry) => !uuid.test(entry)))
				throw new Error(
					"Retained pack installation budget; inspect old installations before proceeding",
				);
			const required = needed.reduce(
				(sum, id) =>
					sum +
					MEMBERS.reduce(
						(bytes, member) => bytes + catalog.engines[id][member].bytes,
						0,
					),
				64 * 1024 ** 2,
			);
			const space = await statfs(installRoot, { bigint: true });
			if (space.bavail * space.bsize < BigInt(required))
				throw new Error(
					"Insufficient space for selected managed pack engines and staging reserve",
				);
			const stage = join(staging, transaction);
			await mkdir(stage, { mode: 0o700 });
			for (const id of needed) {
				signal?.throwIfAborted();
				phase(`Installing ${id} (${needed.indexOf(id) + 1}/${needed.length})`);
				const source = join(sourceRoot, id);
				await directory(source);
				const actual = (await readdir(source)).sort();
				if (JSON.stringify(actual) !== JSON.stringify([...MEMBERS].sort()))
					throw new Error("Managed pack contains missing or untracked members");
				await mkdir(join(stage, id), { mode: 0o700 });
				for (const member of MEMBERS)
					await transfer(
						join(source, member),
						join(stage, id, member),
						catalog.engines[id][member],
						signal,
					);
			}
			signal?.throwIfAborted();
			phase(
				"Committing verified selected engine files; no VM or engine is started",
			);
			if (
				(await pointer(installRoot)).bytes?.toString("hex") !==
				previous.bytes?.toString("hex")
			)
				throw new Error(
					"Managed pack selection changed; retained installation requires inspection",
				);
			// A fresh opaque directory never overwrites an existing installation.
			await rename(stage, join(releases, transaction));
			const value = structuredClone(previous.value);
			for (const id of needed)
				value.engines[id] = { catalogSha256, directory: transaction };
			const temporary = join(installRoot, `active-${transaction}.tmp`);
			const file = await open(temporary, "wx", 0o600);
			try {
				await file.writeFile(JSON.stringify(value));
				await file.sync();
			} finally {
				await file.close();
			}
			signal?.throwIfAborted();
			await rename(temporary, join(installRoot, "active.json"));
			return {
				installed: ids,
				reused,
				catalogSha256,
				activation: "not-implemented",
				engineReadiness: "not-tested",
			};
		} catch (error) {
			operationError = error;
			throw error;
		} finally {
			// Refuse a changed lease even after publication, without discarding the
			// original failure when both installation and lease release fail.
			await releaseLease(lease, leasePath, leaseIdentity, operationError);
		}
	}
	async function verify(
		selection = EMULATION_ENGINES,
		{ signal, phase = () => {} } = {},
	) {
		const ids = selectEmulationEngines(selection);
		if (!catalog)
			throw new Error(
				"This build has no reviewed bundled Emulation Framework Pack",
			);
		await directory(installRoot);
		const selected = await pointer(installRoot);
		for (const id of ids)
			await verifyEngine(id, selected.value.engines[id], signal, phase);
		if (
			(await pointer(installRoot)).bytes?.toString("hex") !==
			selected.bytes?.toString("hex")
		)
			throw new Error("Managed pack selection changed during verification");
		return {
			verified: ids,
			catalogSha256,
			integrity: "verified",
			activation: "not-implemented",
			engineReadiness: "not-tested",
		};
	}
	return Object.freeze({ status, install, verify });
}
