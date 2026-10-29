import { dirname, join } from "node:path";
import { resolveClineDataDir } from "@cline/shared/storage";
import { managedEmulationCatalog } from "./managed-emulation-catalog";
import {
	createManagedEmulationPack,
	selectEmulationEngines,
} from "./managed-emulation-pack.mjs";

function pack() {
	return createManagedEmulationPack({
		sourceRoot: join(
			dirname(process.execPath),
			"resources",
			"emulation-framework-pack",
		),
		installRoot: join(resolveClineDataDir(), "emulation-framework-pack"),
		catalog: managedEmulationCatalog,
	});
}
export const managedEmulationPackStatus = () => pack().status();
let activeInstall: AbortController | undefined;
export async function installManagedEmulationPack(
	selection: unknown,
	phase: (value: string) => void,
) {
	const engines = selectEmulationEngines(selection);
	if (activeInstall)
		throw new Error("A managed pack installation is already running");
	const controller = new AbortController();
	activeInstall = controller;
	try {
		return await pack().install(engines, { phase, signal: controller.signal });
	} finally {
		if (activeInstall === controller) activeInstall = undefined;
	}
}
/** Caller must first verify the exact running Setup Center install job. */
export function cancelManagedEmulationInstall() {
	if (!activeInstall)
		throw new Error("No cancellable emulation pack installation is active");
	activeInstall.abort();
	return { cancellationRequested: true, completed: false };
}
export function verifyManagedEmulationPack(
	selection: unknown,
	phase: (value: string) => void,
) {
	return pack().verify(selectEmulationEngines(selection), { phase });
}
