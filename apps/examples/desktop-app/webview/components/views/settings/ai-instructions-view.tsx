"use client";

import { Check, RotateCcw } from "lucide-react";
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
	const [savedNotice, setSavedNotice] = useState(false);
	const dirty = useMemo(
		() => instructions !== saved.instructions || rules !== saved.rules,
		[instructions, rules, saved],
	);

	const save = () => {
		const next = saveCustomAiInstructions({ instructions, rules });
		setSaved(next);
		setInstructions(next.instructions);
		setRules(next.rules);
		setSavedNotice(true);
		window.setTimeout(() => setSavedNotice(false), 2000);
	};

	const reset = () => {
		setInstructions(saved.instructions);
		setRules(saved.rules);
	};

	return (
		<PageFrame>
			<PageHeader
				description="Set persistent guidance that Cline applies automatically to every new session."
				title="AI Instructions"
			/>

			<div className="max-w-4xl space-y-6">
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