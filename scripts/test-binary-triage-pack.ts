import { BinaryTriageService } from "../apps/examples/desktop-app/sidecar/binary-triage";

let result: Awaited<ReturnType<BinaryTriageService["test"]>>;
try {
	result = await new BinaryTriageService().test();
} catch (error) {
	const message = (
		error instanceof Error ? error.message : "Owned triage test failed"
	)
		.slice(0, 500)
		.replaceAll("%", "%25")
		.replaceAll("\r", "%0D")
		.replaceAll("\n", "%0A");
	console.error(
		`::error title=Binary Triage Pack owned acceptance::${message}`,
	);
	throw error;
}
if (
	result.capabilities.length !== 4 ||
	result.capabilities.some((c) => c.state !== "ready")
) {
	throw new Error("Every bundled triage engine must execute its owned fixture");
}
console.log(
	"Owned Binary Triage Pack fixtures passed; not arbitrary-target or licensed/device validation.",
);
