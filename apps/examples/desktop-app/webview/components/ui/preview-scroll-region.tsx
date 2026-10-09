// biome-ignore-all lint/a11y/noNoninteractiveTabindex: This primitive is intentionally a focusable overflow region for keyboard scrolling, not an interactive widget.
import type { ComponentProps } from "react";
import { cn } from "@/lib/utils";
/** A named, focusable overflow region for keyboard/wheel scrolling, not a widget. */
export function PreviewScrollRegion({
	className,
	...props
}: ComponentProps<"section">) {
	return (
		<section
			{...props}
			tabIndex={0}
			className={cn(
				"min-h-0 flex-1 overflow-auto overscroll-contain rounded-lg border border-border/70 bg-muted/20 focus-visible:outline focus-visible:outline-2 focus-visible:outline-ring",
				className,
			)}
		/>
	);
}
