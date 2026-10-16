import { BinaryTriageService } from "../apps/examples/desktop-app/sidecar/binary-triage";

const result = await new BinaryTriageService().test();
if (
	result.capabilities.length !== 4 ||
	result.capabilities.some((c) => c.state !== "ready")
) {
	throw new Error("Every bundled triage engine must execute its owned fixture");
}
console.log(
	"Owned Binary Triage Pack fixtures passed; not arbitrary-target or licensed/device validation.",
);
