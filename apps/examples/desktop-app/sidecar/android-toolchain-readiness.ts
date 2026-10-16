import { verifyAndroidToolchain, testAndroidToolchain } from "@cline/core";
import { resolveClineDataDir } from "@cline/shared/storage";
import { mkdir, readFile, writeFile, rename, lstat } from "node:fs/promises";
import { join } from "node:path";
const directory = () => join(resolveClineDataDir(), "android-toolchain");
let testing: Promise<unknown> | undefined;
export async function androidToolchainStatus() {
	try {
		const pack = await verifyAndroidToolchain();
		let receipt: { identity?: string; status?: string } | undefined;
		try {
			const file = join(directory(), "owned-receipt.json"),
				info = await lstat(file);
			if (info.isFile() && !info.isSymbolicLink() && info.size < 65536)
				receipt = JSON.parse(await readFile(file, "utf8"));
		} catch {}
		const ready =
			receipt?.identity === pack.identity && receipt?.status === "passed";
		return {
			state: ready ? "ready" : "installed-not-tested",
			identity: pack.identity,
			receipt: ready ? receipt : undefined,
			coverage:
				"Owned fixture readiness is separate from target support, valid AAB coverage, ART and device compatibility",
		};
	} catch {
		return {
			state: "needs-setup",
			coverage:
				"Pinned Android resources missing or integrity verification failed; no fallback readiness claim",
		};
	}
}
export function testOwnedAndroidToolchain() {
	if (testing) return testing;
	testing = (async () => {
		const result = await testAndroidToolchain();
		await mkdir(directory(), { recursive: true, mode: 0o700 });
		if ((await lstat(directory())).isSymbolicLink())
			throw new Error("Linked Android readiness directory forbidden");
		const file = join(directory(), "owned-receipt.json"),
			temporary = file + ".tmp";
		await writeFile(temporary, JSON.stringify(result), { mode: 0o600 });
		await rename(temporary, file);
		return result;
	})().finally(() => {
		testing = undefined;
	});
	return testing;
}
