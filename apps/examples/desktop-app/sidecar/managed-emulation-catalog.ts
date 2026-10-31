import type { ManagedPackCatalog } from "./managed-emulation-pack.mjs";

// Production pins must be compiled into the sidecar with the reviewed bundled
// guest images, corresponding sources and notices. A resource-side JSON file,
// user setting, environment variable or IPC request cannot supply these pins.
// Development guest-test images are deliberately not promoted to installable.
export const managedEmulationCatalog: ManagedPackCatalog | null = null;
