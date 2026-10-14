"use client";
import { useEffect, useState } from "react";
import { desktopClient } from "@/lib/desktop-client";
export function BackendConnectionStatus() {
	const [state, setState] = useState(
		() => desktopClient.getTransportState?.() ?? "unavailable",
	);
	useEffect(() => desktopClient.subscribeTransportState?.(setState), []);
	return (
		<output className="text-xs text-muted-foreground">
			Backend: {state}.{" "}
			{state !== "connected" &&
				"Read-only status may reconnect. Accepted actions are never replayed by this indicator; inspect job state before retrying."}
		</output>
	);
}
