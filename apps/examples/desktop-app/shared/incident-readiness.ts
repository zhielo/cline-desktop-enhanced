export type Row = {
	tool: string;
	state:
		| "installed"
		| "execution-verified"
		| "task-ready"
		| "blocked"
		| "unverified";
	evidence: string;
};
export function ownedFixtureRows(value: unknown): Row[] {
	const result = (
		value as { result?: { result?: { evidence?: { checks?: unknown[] } } } }
	)?.result?.result;
	return (result?.evidence?.checks ?? []).slice(0, 10).flatMap((check) => {
		const c = check as {
			engine?: unknown;
			status?: unknown;
			executionVerified?: unknown;
			scope?: unknown;
		};
		if (typeof c.engine !== "string") return [];
		return [
			{
				tool: c.engine,
				state:
					c.status === "completed" &&
					c.executionVerified === true &&
					c.scope === "owned-static-fixture-only"
						? "execution-verified"
						: "blocked",
				evidence:
					"Owned static fixture only; not validation of arbitrary targets or live devices",
			} satisfies Row,
		];
	});
}
