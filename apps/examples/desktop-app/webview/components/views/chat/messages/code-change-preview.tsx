"use client";
import { type ReactNode, useState } from "react";
import { Button } from "@/components/ui/button";
import {
	Dialog,
	DialogContent,
	DialogDescription,
	DialogHeader,
	DialogTitle,
} from "@/components/ui/dialog";
import { PreviewScrollRegion } from "@/components/ui/preview-scroll-region";

/** Recorded tool data only: never fetch/execute a possibly newer filesystem file. */
export function CodeChangePreview({
	children,
	path,
	newText,
	oldText,
	diff,
	fragment = false,
}: {
	children: ReactNode;
	path: string;
	newText?: string;
	oldText?: string;
	diff?: string;
	fragment?: boolean;
}) {
	const [open, setOpen] = useState(false);
	const [side, setSide] = useState<"after" | "before">("after");
	const text = side === "before" ? (oldText ?? "") : (newText ?? diff ?? "");
	const limit = 200_000;
	return (
		<>
			<RecordedCodeTrigger
				path={path}
				onActivate={() => {
					setSide("after");
					setOpen(true);
				}}
			>
				{children}
			</RecordedCodeTrigger>
			<Dialog open={open} onOpenChange={setOpen}>
				<DialogContent className="flex max-h-[80vh] flex-col gap-3 overflow-hidden sm:max-w-3xl">
					<DialogHeader className="shrink-0">
						<DialogTitle className="break-all pr-8 font-mono text-sm">
							{path}
						</DialogTitle>
						<DialogDescription>
							{fragment
								? "Recorded change fragment — not the full or current file."
								: diff && newText === undefined
									? "Recorded diff — not the current file."
									: "Recorded code from this tool call — read-only, not the current file."}
						</DialogDescription>
					</DialogHeader>
					{newText !== undefined && oldText !== undefined && (
						<div className="flex shrink-0 gap-2">
							<Button
								size="sm"
								variant={side === "after" ? "secondary" : "ghost"}
								aria-pressed={side === "after"}
								onClick={() => setSide("after")}
							>
								After change
							</Button>
							<Button
								size="sm"
								variant={side === "before" ? "secondary" : "ghost"}
								aria-pressed={side === "before"}
								onClick={() => setSide("before")}
							>
								Before change
							</Button>
						</div>
					)}
					{text.length > limit && (
						<p className="shrink-0 text-xs text-muted-foreground">
							Preview limited to the first {limit.toLocaleString()} characters;
							remaining recorded code is not displayed.
						</p>
					)}
					<PreviewScrollRegion
						aria-label="Recorded code content"
						data-testid="recorded-code-scroll"
					>
						<pre className="min-w-max p-4 font-mono text-xs leading-5">
							<code>{text.slice(0, limit)}</code>
						</pre>
					</PreviewScrollRegion>
				</DialogContent>
			</Dialog>
		</>
	);
}

function RecordedCodeTrigger({
	children,
	path,
	onActivate,
}: {
	children: ReactNode;
	path: string;
	onActivate: () => void;
}) {
	return (
		// biome-ignore lint/a11y/useSemanticElements: The selectable rich diff contains block/custom-element content; avoid nested native buttons.
		<div
			aria-label={`View recorded code change for ${path}`}
			aria-haspopup="dialog"
			className="mt-1 cursor-pointer rounded focus-visible:outline focus-visible:outline-2 focus-visible:outline-ring"
			data-testid="recorded-code-trigger"
			role="button"
			tabIndex={0}
			onClick={() => {
				if (!window.getSelection()?.toString()) onActivate();
			}}
			onKeyDown={(e) => {
				if (
					e.target === e.currentTarget &&
					(e.key === "Enter" || e.key === " ")
				) {
					e.preventDefault();
					onActivate();
				}
			}}
		>
			{children}
		</div>
	);
}
