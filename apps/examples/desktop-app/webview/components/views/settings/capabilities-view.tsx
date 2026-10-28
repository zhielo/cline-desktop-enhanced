"use client";
import {
	AGENDA_TODO_ENABLED,
	DESKTOP_CHANNELS_VISIBLE,
} from "@cline/shared/browser";
import { useState } from "react";
import { SessionToolInventoryPanel } from "./session-tool-inventory";
import catalog from "@/lib/desktop-capability-catalog.json";

/** A source-backed map, deliberately distinct from live Setup Center checks. */
export function CapabilitiesView() {
	const [query, setQuery] = useState("");
	const needle = query.trim().toLocaleLowerCase();
	const features = catalog.features.filter((feature) =>
		[
			feature.domain,
			feature.status,
			feature.verified_scope,
			feature.gap_or_next_step,
		].some((value) => value.toLocaleLowerCase().includes(needle)),
	);
	return (
		<section
			className="h-full overflow-auto p-6 space-y-4"
			aria-labelledby="capability-heading"
		>
			<h1 id="capability-heading" className="text-lg font-semibold">
				Capabilities
			</h1>
			<p className="text-sm text-muted-foreground">
				Source inventory, not a readiness certificate. Provider access, model
				vision, installed engines and device availability require live checks in
				API Providers, Diagnostics and Setup Center. No checks or paid requests
				run on this page.
			</p>
			<p className="text-sm">
				Agenda: {AGENDA_TODO_ENABLED ? "enabled" : "disabled"}. Channels
				navigation: {DESKTOP_CHANNELS_VISIBLE ? "visible" : "hidden"}. Existing
				feature implementations are preserved.
			</p>
			<SessionToolInventoryPanel />
			<label className="block text-sm">
				Filter capabilities
				<input
					className="mt-1 block w-full rounded border bg-background p-2"
					type="search"
					value={query}
					onChange={(event) => setQuery(event.target.value)}
				/>
			</label>
			<output className="block text-sm">
				{features.length} of {catalog.features.length} feature families
			</output>
			{features.map((feature) => (
				<article key={feature.domain} className="rounded border p-4 space-y-2">
					<h2 className="font-semibold">{feature.domain}</h2>
					<p className="text-sm">Support: {feature.status}</p>
					<p className="text-sm">{feature.verified_scope}</p>
					<p className="text-sm text-muted-foreground">
						Limit / next step: {feature.gap_or_next_step}
					</p>
					<p className="text-sm">Validation target: {feature.acceptance}</p>
				</article>
			))}
		</section>
	);
}
