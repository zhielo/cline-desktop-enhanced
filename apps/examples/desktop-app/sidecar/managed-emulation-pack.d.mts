export type EmulationEngine = "qiling" | "unidbg" | "rnidbg" | "speakeasy";
export type ManagedPackCatalog = {
	schemaVersion: 1;
	releaseId: string;
	engines: Record<
		EmulationEngine,
		Record<
			| "guest.iso"
			| "image-manifest.json"
			| "NOTICES.txt"
			| "corresponding-source.tar.zst",
			{ bytes: number; sha256: string }
		>
	>;
};
export type ManagedPackStatus = {
	available: boolean;
	activation: "not-implemented";
	engineReadiness: "not-tested";
	engines: {
		id: EmulationEngine;
		status: "not-installed" | "installed-unverified" | "stale";
	}[];
};
export type ManagedPackOperation = {
	signal?: AbortSignal;
	phase?: (value: string) => void;
};
export const EMULATION_ENGINES: readonly EmulationEngine[];
export function selectEmulationEngines(selection: unknown): EmulationEngine[];
export function createManagedEmulationPack(options: {
	sourceRoot: string;
	installRoot: string;
	catalog: ManagedPackCatalog | null;
}): {
	status(): Promise<ManagedPackStatus>;
	install(
		selection?: readonly EmulationEngine[],
		operation?: ManagedPackOperation,
	): Promise<{
		installed: EmulationEngine[];
		reused: EmulationEngine[];
		catalogSha256: string;
		activation: "not-implemented";
		engineReadiness: "not-tested";
	}>;
	verify(
		selection?: readonly EmulationEngine[],
		operation?: ManagedPackOperation,
	): Promise<{
		verified: EmulationEngine[];
		catalogSha256: string;
		integrity: "verified";
		activation: "not-implemented";
		engineReadiness: "not-tested";
	}>;
};
