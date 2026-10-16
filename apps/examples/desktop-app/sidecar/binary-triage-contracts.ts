import { z } from "zod";

export const TRIAGE_OPERATIONS = [
	"inspect_binary",
	"list_functions",
	"get_function_disassembly",
	"find_references",
	"scan_yara",
	"identify_capabilities",
	"extract_strings",
] as const;
export const TriageRequest = z
	.object({
		operation: z.enum(TRIAGE_OPERATIONS),
		target: z
			.string()
			.min(1)
			.max(4096)
			.refine((v) => !/[\0\r\n]/.test(v)),
		address: z
			.string()
			.regex(/^0x[0-9a-fA-F]{1,13}$/)
			.optional(),
		question: z.string().trim().min(1).max(500),
	})
	.strict()
	.superRefine((v, ctx) => {
		const selected = ["get_function_disassembly", "find_references"].includes(
			v.operation,
		);
		if (selected !== (v.address !== undefined))
			ctx.addIssue({
				code: "custom",
				message:
					"Exact hexadecimal address required only for selected-address operations",
			});
	});
export type TriageInput = z.infer<typeof TriageRequest>;
export type CapabilityState =
	| "ready"
	| "needs-setup"
	| "installed-not-tested"
	| "unsupported"
	| "integrity-failed";
export type TriageCapability = {
	id: string;
	state: CapabilityState;
	reason: string;
	version?: string;
	testedAt?: string;
};
export function triageEngine(operation: TriageInput["operation"]) {
	return operation === "scan_yara"
		? "yara"
		: operation === "identify_capabilities"
			? "capa"
			: operation === "extract_strings"
				? "floss"
				: "radare2";
}
export const TRIAGE_LIMITATIONS = [
	"Static selected-input evidence only; observed bytes, rule matches and derived capabilities are distinct.",
	"No match does not mean safe; inferred capabilities and references do not prove execution.",
	"No debugger, target execution, arbitrary commands/scripts, network endpoints or FLOSS decoding are exposed.",
	"Process deadlines and byte budgets are not an OS sandbox or a total memory guarantee.",
	"Hashes establish integrity, not behavioral correctness or producer authentication. Review before sharing.",
] as const;
