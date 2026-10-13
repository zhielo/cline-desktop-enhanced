import { byteDigest } from "./contracts";

type Primitive = {
	type: string;
	value?: string | number | boolean | null;
	sha256?: string;
	truncated?: boolean;
	opaque?: true;
};
export type ConsoleProtocolReport = {
	method: string;
	receivedAt: number;
	protocolTimestamp: number;
	scriptId: string;
	line: number;
	column: number;
	arguments: Primitive[];
	argumentsTruncated: boolean;
};
/** Only protocol-supplied primitive values, never object previews/IDs or property retrieval. */
function primitive(value: unknown): Primitive {
	if (!value || typeof value !== "object")
		return { type: "unknown", opaque: true };
	const v = value as Record<string, unknown>;
	if (
		v.type === "string" &&
		typeof v.value === "string" &&
		v.value.length <= 16384
	)
		return {
			type: "string",
			value: v.value.slice(0, 160),
			sha256: byteDigest(Buffer.from(v.value)),
			truncated: v.value.length > 160,
		};
	if (v.type === "boolean" && typeof v.value === "boolean")
		return { type: "boolean", value: v.value };
	if (
		v.type === "number" &&
		typeof v.value === "number" &&
		Number.isFinite(v.value)
	)
		return { type: "number", value: v.value };
	if (v.type === "undefined") return { type: "undefined" };
	if (v.type === "object" && v.subtype === "null" && v.value === null)
		return { type: "null", value: null };
	if (
		(v.type === "number" || v.type === "bigint") &&
		typeof v.unserializableValue === "string" &&
		(v.type === "number"
			? /^(?:NaN|Infinity|-Infinity|-0)$/
			: /^-?\d{1,128}n$/
		).test(v.unserializableValue)
	)
		return { type: v.type, value: v.unserializableValue };
	return { type: "opaque", opaque: true };
}
/** Bounded receipt window (+ sub-millisecond receipt rounding only). Target timestamps and stack labels are untrusted protocol claims. */
export class InspectorConsoleCollector {
	private after?: number;
	private active = false;
	private reports: ConsoleProtocolReport[] = [];
	dropped = 0;
	saturated = false;
	start(now: number) {
		this.after = now;
		this.active = true;
	}
	stop() {
		this.active = false;
	}
	accept(value: unknown, receivedAt: number) {
		if (!this.active || this.after === undefined) return;
		if (this.reports.length >= 24) {
			this.saturated = true;
			return;
		}
		const p = value as Record<string, unknown> | null;
		const frames = (p?.stackTrace as { callFrames?: unknown })?.callFrames;
		const frame = Array.isArray(frames)
			? (frames[0] as Record<string, unknown> | undefined)
			: undefined;
		if (
			!p ||
			typeof p.type !== "string" ||
			!["log", "debug", "info", "warning", "error", "assert"].includes(
				p.type,
			) ||
			typeof p.timestamp !== "number" ||
			!Number.isFinite(p.timestamp) ||
			p.timestamp < this.after ||
			p.timestamp >= receivedAt + 1 ||
			!frame ||
			typeof frame.scriptId !== "string" ||
			frame.scriptId.length > 80 ||
			!frame.scriptId ||
			!Number.isSafeInteger(frame.lineNumber) ||
			Number(frame.lineNumber) < 0 ||
			Number(frame.lineNumber) > 1000000 ||
			!Number.isSafeInteger(frame.columnNumber) ||
			Number(frame.columnNumber) < 0 ||
			Number(frame.columnNumber) > 1048576 ||
			!Array.isArray(p.args)
		) {
			this.dropped++;
			return;
		}
		this.reports.push({
			method: p.type,
			receivedAt,
			protocolTimestamp: p.timestamp,
			scriptId: frame.scriptId,
			line: Number(frame.lineNumber),
			column: Number(frame.columnNumber),
			arguments: p.args.slice(0, 8).map(primitive),
			argumentsTruncated: p.args.length > 8,
		});
	}
	reconcile(
		scripts: Array<{
			scriptId: string;
			staticMatch?: boolean;
			sha256?: string;
		}>,
		targetHash: string,
	) {
		const bound: Array<
			ConsoleProtocolReport & {
				sourceSha256: string;
				association: "source-bound-protocol-report";
			}
		> = [];
		let unbound = 0;
		for (const report of this.reports) {
			const candidates = scripts.filter((s) => s.scriptId === report.scriptId);
			if (
				candidates.length !== 1 ||
				!candidates[0].staticMatch ||
				candidates[0].sha256 !== targetHash
			) {
				unbound++;
				continue;
			}
			bound.push({
				...report,
				sourceSha256: targetHash,
				association: "source-bound-protocol-report",
			});
		}
		return {
			reports: bound,
			discarded: this.dropped + unbound,
			saturated: this.saturated,
			verifiedBehavior: false as const,
			note: "Console events, timestamps and coordinates are target-supplied protocol claims. Exact source bytes do not authenticate VM execution or a scenario outcome. Objects remain opaque. Missing reports are not absence; replay/history and clock differences can be discarded.",
		};
	}
}
