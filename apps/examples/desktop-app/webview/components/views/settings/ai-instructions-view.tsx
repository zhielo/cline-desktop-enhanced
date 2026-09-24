"use client";

import { Check, RotateCcw, ShieldCheck } from "lucide-react";
import { useMemo, useState } from "react";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import {
	readCustomAiInstructions,
	saveCustomAiInstructions,
} from "@/lib/custom-ai-instructions";
import { PageFrame, PageHeader } from "../page-layout";

export function AiInstructionsView() {
	const [saved, setSaved] = useState(readCustomAiInstructions);
	const [instructions, setInstructions] = useState(saved.instructions);
	const [rules, setRules] = useState(saved.rules);
	const [profile, setProfile] = useState(saved.profile);
	const [savedNotice, setSavedNotice] = useState(false);
	const dirty = useMemo(
		() =>
			instructions !== saved.instructions ||
			rules !== saved.rules ||
			profile !== saved.profile,
		[instructions, profile, rules, saved],
	);

	const save = () => {
		const next = saveCustomAiInstructions({ profile, instructions, rules });
		setSaved(next);
		setInstructions(next.instructions);
		setRules(next.rules);
		setProfile(next.profile);
		setSavedNotice(true);
		window.setTimeout(() => setSavedNotice(false), 2000);
	};

	const reset = () => {
		setInstructions(saved.instructions);
		setRules(saved.rules);
		setProfile(saved.profile);
	};

	return (
		<PageFrame>
			<PageHeader
				description="Set persistent guidance that Cline applies automatically to every new session."
				title="AI Instructions"
			/>

			<div className="max-w-4xl space-y-6">
				<section className="space-y-3">
					<div>
						<h2 className="text-base font-semibold">Working profile</h2>
						<p className="text-sm text-muted-foreground">
							Choose the default execution style for new sessions.
						</p>
					</div>
					<div className="grid gap-3 sm:grid-cols-2">
						<button
							aria-pressed={profile === "standard"}
							className={`rounded-lg border p-4 text-left transition-colors ${
								profile === "standard"
									? "border-primary/60 bg-primary/5"
									: "border-border hover:bg-muted/40"
							}`}
							onClick={() => setProfile("standard")}
							type="button"
						>
							<span className="block text-sm font-semibold">Standard</span>
							<span className="mt-1 block text-xs text-muted-foreground">
								Balanced behavior for normal development work.
							</span>
						</button>
						<button
							aria-pressed={profile === "ctf"}
							className={`rounded-lg border p-4 text-left transition-colors ${
								profile === "ctf"
									? "border-orange-500/60 bg-orange-500/10"
									: "border-border hover:bg-muted/40"
							}`}
							onClick={() => setProfile("ctf")}
							type="button"
						>
							<span className="flex items-center gap-2 text-sm font-semibold">
								<ShieldCheck className="size-4 text-orange-500" />
								CTF Mode
							</span>
							<span className="mt-1 block text-xs text-muted-foreground">
								Proactive commands, debugging, static analysis, and
								reverse-engineering for authorized targets.
							</span>
						</button>
					</div>
					{profile === "ctf" ? (
						<p className="rounded-md border border-orange-500/30 bg-orange-500/10 p-3 text-xs leading-5 text-orange-700 dark:text-orange-300">
							CTF Mode applies an authorization-aware technical preset in
							addition to your instructions. Full Access controls tool
							approvals; core safety boundaries still apply.
						</p>
					) : null}
				</section>

				<section className="space-y-2">
					<div>
						<h2 className="text-base font-semibold">Custom instructions</h2>
						<p className="text-sm text-muted-foreground">
							Describe how Cline should work, communicate, and make decisions.
						</p>
					</div>
					<Textarea
						aria-label="Custom AI instructions"
						className="min-h-56 resize-y font-mono text-sm"
						onChange={(event) => setInstructions(event.target.value)}
						placeholder="Example: Be concise. Inspect the existing implementation before editing. Explain important tradeoffs and verify the result."
						value={instructions}
					/>
					<p className="text-right text-xs text-muted-foreground">
						{instructions.length.toLocaleString()} characters
					</p>
				</section>

				<section className="space-y-2">
					<div>
						<h2 className="text-base font-semibold">Rules and constraints</h2>
						<p className="text-sm text-muted-foreground">
							Add non-negotiable requirements, validation steps, or project
							conventions.
						</p>
					</div>
					<Textarea
						aria-label="Global AI rules"
						className="min-h-40 resize-y font-mono text-sm"
						onChange={(event) => setRules(event.target.value)}
						placeholder="Example: Run type-checks and focused tests before marking work complete. Never expose credentials."
						value={rules}
					/>
				</section>

				<div className="flex items-center justify-between border-t pt-4">
					<p className="text-xs text-muted-foreground">
						Saved instructions apply to new sessions. Existing sessions keep
						their current configuration.
					</p>
					<div className="flex items-center gap-2">
						{savedNotice ? (
							<span className="flex items-center gap-1 text-xs text-emerald-500">
								<Check className="size-3.5" />
								Saved
							</span>
						) : null}
						<Button
							disabled={!dirty}
							onClick={reset}
							size="sm"
							type="button"
							variant="outline"
						>
							<RotateCcw className="size-3.5" />
							Reset
						</Button>
						<Button disabled={!dirty} onClick={save} size="sm" type="button">
							Save instructions
						</Button>
					</div>
				</div>
			</div>
		</PageFrame>
	);
}