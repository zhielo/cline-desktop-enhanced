import { expect, it } from "vitest";
import { assertAdmittedApplicationManifest as check } from "./application-bindings";
const source = (path: string, sha256 = "a".repeat(64), bytes = 42) => ({
	path,
	sha256,
	bytes,
});
it("binds one common directory, ASAR or single-file prefix to admitted identities", () => {
	for (const prefix of ["", "folder/", "folder/app.asar!/"])
		check(
			[source("a.js"), source("sub/a.js")],
			[
				source(prefix + "a.js"),
				source(prefix + "sub/a.js"),
				source(prefix + "owned.dll"),
			],
		);
	check([source("é.js")], [source("folder/e\u0301.js")]);
	check([], [source("owned.dll")]);
});
it("rejects unrelated bytes, wrong counts, duplicate or mixed-prefix suffix matches", () => {
	for (const admitted of [
		[source("folder/a.js", "b".repeat(64))],
		[source("folder/a.js", "a".repeat(64), 43)],
		[],
		[source("folder/a.js"), source("other/a.js")],
	])
		expect(() => check([source("a.js")], admitted)).toThrow(/binding/);
	expect(() =>
		check(
			[source("a.js"), source("b.js")],
			[source("first/a.js"), source("second/b.js")],
		),
	).toThrow(/binding/);
	expect(() =>
		check([source("a.js"), source("a.js")], [source("a.js"), source("b.js")]),
	).toThrow(/binding/);
});
