import { expect, test } from "bun:test";
import { annotationFromSummary } from "./report-installed-acceptance.mjs";
test("failure annotations are bounded, escaped and redact credentials", () => {
	expect(annotationFromSummary({status:"passed"})).toBeUndefined();
	const text = annotationFromSummary({status:"failed",stages:["owned-stage","bad\nstage"],
		reason:'Bearer private-secret\n"apiKey":"secret" ' + "a".repeat(64) + "%"});
	expect(text).toContain("owned-stage");
	expect(text).not.toContain("private-secret");
	expect(text).not.toContain('"secret"');
	expect(text).toContain("%0A");
	expect(text).toContain("%25");
});