import x64 from "../../../../scripts/fixtures/owned-native-elf.json";
import arm32 from "../../../../scripts/fixtures/owned-arm32-elf.json";
import arm64 from "../../../../scripts/fixtures/owned-arm64-elf.json";
export const GHIDRA_ACCEPTANCE_ARCHITECTURES = [
	"x86_64",
	"arm32",
	"arm64",
] as const;
export type GhidraAcceptanceArchitecture =
	(typeof GHIDRA_ACCEPTANCE_ARCHITECTURES)[number];
export function ghidraAcceptanceFixture(architecture: string) {
	switch (architecture) {
		case "x86_64":
			return { ...x64, architecture, languagePrefix: "x86:LE:64:" };
		case "arm32":
			return { ...arm32, languagePrefix: "ARM:LE:32:" };
		case "arm64":
			return { ...arm64, languagePrefix: "AARCH64:LE:64:" };
		default:
			throw new Error("Unsupported Ghidra acceptance architecture");
	}
}
