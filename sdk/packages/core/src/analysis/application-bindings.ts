type SourceIdentity = { path: string; sha256: string; bytes: number };
const included = (path: string) =>
	/\.(?:[cm]?[jt]s|[jt]sx|map|json|html?|node)$/i.test(path);
/** Bind normalized virtual source identities to the exact admitted receipt inventory.
 * A single common prefix handles directory, ASAR and single-file targets without
 * reopening possibly changed target files or treating a suffix match as identity.
 */
export function assertAdmittedApplicationManifest(
	manifest: readonly SourceIdentity[],
	artifacts: readonly SourceIdentity[],
) {
	const admitted = artifacts
		.filter((f) => included(f.path))
		.map((f) => ({ ...f, path: f.path.normalize("NFC") }));
	if (manifest.length !== admitted.length)
		throw new Error(
			"Application evidence binding mismatch: source inventory count",
		);
	if (!manifest.length) return;
	const key = (f: SourceIdentity) =>
		JSON.stringify([f.path, f.sha256, f.bytes]);
	const identities = new Set(admitted.map(key));
	if (identities.size !== admitted.length)
		throw new Error(
			"Application evidence binding mismatch: duplicate inventory",
		);
	const first = manifest[0]!;
	const prefixes = admitted
		.filter(
			(f) =>
				f.sha256 === first.sha256 &&
				f.bytes === first.bytes &&
				f.path.endsWith(first.path),
		)
		.map((f) => f.path.slice(0, -first.path.length))
		.filter((p) => !p || p.endsWith("/") || p.endsWith("!/"));
	if (
		!prefixes.some((prefix) => {
			const projected = manifest.map((f) =>
				key({ ...f, path: prefix + f.path }),
			);
			return (
				new Set(projected).size === admitted.length &&
				projected.every((k) => identities.has(k))
			);
		})
	)
		throw new Error(
			"Application evidence binding mismatch: admitted source identities",
		);
}
