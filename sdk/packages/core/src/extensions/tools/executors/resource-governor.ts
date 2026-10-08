import { freemem } from "node:os";
export type ResourceProfile = "economy" | "balanced" | "deep";
type Pending = {
	mb: number;
	resident: boolean;
	resolve: (release: () => void) => void;
	reject: (error: Error) => void;
	signal?: AbortSignal;
	abort: () => void;
	timer: ReturnType<typeof setTimeout>;
};
/** Shared within one owning process, not an OS sandbox or machine-wide lease.
 * Reservations are estimates; existing native/process hard limits stay intact. */
export class ResourceGovernor {
	private active = 0;
	private residents = 0;
	private reservedMB = 0;
	private queue: Pending[] = [];
	private peak = 0;
	private wakeTimer: ReturnType<typeof setTimeout> | undefined;
	private profile: ResourceProfile = "balanced";
	constructor(private availableMB = () => freemem() / 1024 / 1024) {}
	setProfile(profile: ResourceProfile) {
		if (!["economy", "balanced", "deep"].includes(profile))
			throw new Error("Unknown resource profile");
		this.profile = profile;
		this.drain();
	}
	snapshot() {
		return {
			scope: "owning-process",
			profile: this.profile,
			active: this.active,
			residentNative: this.residents,
			queued: this.queue.length,
			reservedMB: this.reservedMB,
			peakActive: this.peak,
			maxConcurrent: this.profile === "economy" ? 1 : 2,
			hardMemoryEnforcement: false,
		};
	}
	acquire(
		mb = 128,
		signal?: AbortSignal,
		timeoutMs = 60000,
		resident = false,
	): Promise<() => void> {
		if (
			!Number.isFinite(mb) ||
			mb < 1 ||
			mb > 1024 ||
			!Number.isFinite(timeoutMs) ||
			timeoutMs < 1 ||
			timeoutMs > 300000
		)
			return Promise.reject(new Error("Invalid resource reservation"));
		if (signal?.aborted)
			return Promise.reject(new Error("Resource request cancelled"));
		if (this.queue.length >= 32)
			return Promise.reject(
				new Error("Resource queue full; retry after existing work completes"),
			);
		return new Promise((resolve, reject) => {
			const entry: Pending = {
				mb,
				resident,
				resolve,
				reject,
				signal,
				abort: () => {},
				timer: undefined as unknown as ReturnType<typeof setTimeout>,
			};
			const remove = (message: string) => {
				const index = this.queue.indexOf(entry);
				if (index < 0) return;
				this.queue.splice(index, 1);
				clearTimeout(entry.timer);
				signal?.removeEventListener("abort", entry.abort);
				reject(new Error(message));
				this.drain();
			};
			entry.abort = () => remove("Resource request cancelled");
			entry.timer = setTimeout(
				() => remove("Resource admission timed out; no work launched"),
				timeoutMs,
			);
			signal?.addEventListener("abort", entry.abort, { once: true });
			this.queue.push(entry);
			this.drain();
		});
	}
	private drain() {
		if (this.wakeTimer) clearTimeout(this.wakeTimer);
		this.wakeTimer = undefined;
		const concurrency = this.profile === "economy" ? 1 : 2;
		const budget = this.profile === "deep" ? 1536 : 1024;
		while (this.queue.length) {
			const next = this.queue[0];
			if (!next.resident && this.active >= concurrency) return;
			if (
				this.reservedMB + next.mb > budget ||
				this.availableMB() < next.mb + 256
			) {
				this.wakeTimer = setTimeout(() => this.drain(), 1000);
				this.wakeTimer.unref?.();
				return;
			}
			this.queue.shift();
			clearTimeout(next.timer);
			next.signal?.removeEventListener("abort", next.abort);
			if (next.resident) this.residents++;
			else this.active++;
			this.reservedMB += next.mb;
			this.peak = Math.max(this.peak, this.active);
			let released = false;
			next.resolve(() => {
				if (released) return;
				released = true;
				if (next.resident) this.residents--;
				else this.active--;
				this.reservedMB -= next.mb;
				this.drain();
			});
		}
	}
}
export const analysisResourceGovernor = new ResourceGovernor();

const inheritedProfile = process.env.CLINE_RESOURCE_PROFILE;
if (
	inheritedProfile === "economy" ||
	inheritedProfile === "balanced" ||
	inheritedProfile === "deep"
)
	analysisResourceGovernor.setProfile(inheritedProfile);
