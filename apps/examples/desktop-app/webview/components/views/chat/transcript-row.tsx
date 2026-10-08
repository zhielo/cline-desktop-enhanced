"use client";
import type { ReactNode } from "react";
/** Browser-native variable-height render containment: DOM/search/accessibility
 * remain intact. Live tail is never skipped; no guessed spacer heights. */
export function TranscriptRow({
	children,
	deferred,
}: {
	children: ReactNode;
	deferred: boolean;
}) {
	if (!deferred) return <>{children}</>;
	return (
		<div
			data-transcript-deferred={deferred || undefined}
			style={
				deferred
					? { contentVisibility: "auto", containIntrinsicSize: "auto 600px" }
					: undefined
			}
		>
			{children}
		</div>
	);
}
