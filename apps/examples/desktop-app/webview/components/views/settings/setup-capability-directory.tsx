"use client";
import { useState } from "react";

export type CapabilityRoute = {
	id: string;
	tool?: string;
	operation?: string;
	advanced_action?: string | null;
	prepareCommand?: string;
	runCommand?: string;
	purpose?: string;
	scope?: string;
	requirement?: string;
	limitation?: string;
};
export type SetupCapabilityDirectory = {
	engineRoutes: CapabilityRoute[];
	specialistRoutes: CapabilityRoute[];
	additionalRoutes: CapabilityRoute[];
	binaryTriage: CapabilityRoute[];
	firstParty: CapabilityRoute;
};
export type OptionalFramework = {
	id: string;
	configuration:
		| "not-configured"
		| "invalid-configuration"
		| "configured-not-tested";
	installation: "not-bundled-or-managed";
	readiness: "not-established";
};
const configurationLabels = {
	"not-configured": "Not configured",
	"invalid-configuration": "Configuration incomplete or invalid",
	"configured-not-tested": "Configured, not tested",
};

/** Displays the backend's registered routes; never invents model exposure or readiness. */
export function SetupCapabilityDirectoryView({
	catalog,
	frameworks,
}: {
	catalog?: SetupCapabilityDirectory;
	frameworks?: OptionalFramework[];
}) {
	const [filter, setFilter] = useState("");
	const rows = catalog
		? [
				...catalog.engineRoutes,
				...catalog.specialistRoutes,
				...catalog.additionalRoutes,
				...catalog.binaryTriage,
				catalog.firstParty,
			]
		: [];
	return (
		<section
			aria-label="Frameworks and AI route directory"
			className="space-y-3 rounded-md border p-4"
		>
			<h3 className="font-semibold">Frameworks and AI route directory</h3>
			<p>
				Registered routes are not proof that a tool is exposed to the current
				model. Session mode, enabled tools, installation, fresh tests and
				separate execution approval still apply. Opening this directory runs no
				tests and installs nothing.
			</p>
			<h4 className="font-semibold">Optional isolated emulation frameworks</h4>
			<p>
				Qiling, unidbg, rnidbg and Speakeasy are not included in Install all
				supported components. App-managed Install → Test → Use is not
				implemented in this build. Existing Unicorn is preserved.
			</p>
			<div className="grid gap-3 md:grid-cols-2">
				{["qiling", "unidbg", "rnidbg", "speakeasy"].map((id) => {
					const route = catalog?.specialistRoutes.find((row) => row.id === id);
					const state = frameworks?.find((row) => row.id === id);
					return (
						<article
							key={id}
							className="space-y-2 rounded border p-3"
							aria-label={`${id} framework`}
						>
							<h5 className="font-semibold">
								{id === "qiling"
									? "Qiling"
									: id === "speakeasy"
										? "Speakeasy"
										: id}
							</h5>
							<p>
								{state
									? configurationLabels[state.configuration]
									: "Configuration status unavailable"}
								. Readiness not established.
							</p>
							<p className="text-sm">
								{route?.scope ??
									"Profile scope unavailable; no architecture or target support inferred."}
							</p>
							{route && <p className="text-sm">{route.requirement}</p>}
							{route?.prepareCommand && (
								<p className="text-sm">
									Approved runtime route: <code>{route.prepareCommand}</code> →{" "}
									<code>{route.runCommand}</code>
								</p>
							)}
						</article>
					);
				})}
			</div>
			<details>
				<summary>Registered capability routes ({rows.length})</summary>
				<label className="block">
					Filter registered routes
					<input
						className="block w-full rounded border p-2"
						value={filter}
						onChange={(event) => setFilter(event.target.value)}
					/>
				</label>
				{!catalog && (
					<p>Backend catalog unavailable. No capabilities inferred.</p>
				)}
				<ul className="space-y-3">
					{rows
						.filter((row) =>
							`${row.id} ${row.purpose ?? ""} ${row.scope ?? ""} ${row.operation ?? ""}`
								.toLowerCase()
								.includes(filter.toLowerCase()),
						)
						.map((row) => (
							<li
								key={`${row.id}:${row.operation}`}
								className="rounded border p-3"
							>
								<strong>{row.id}</strong>
								<p className="text-sm">
									{[row.tool, row.operation, row.advanced_action]
										.filter(Boolean)
										.join(" → ") || "Runtime workbench only"}
								</p>
								<p className="text-sm">
									{row.purpose ?? row.scope ?? row.requirement}
								</p>
								{row.requirement && (row.purpose || row.scope) && (
									<p className="text-sm">{row.requirement}</p>
								)}
								{row.limitation && <p className="text-sm">{row.limitation}</p>}
							</li>
						))}
				</ul>
			</details>
		</section>
	);
}
