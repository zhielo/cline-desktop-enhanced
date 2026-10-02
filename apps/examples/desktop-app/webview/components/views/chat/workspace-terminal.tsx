"use client";

import {
	CircleStop,
	Loader2,
	Play,
	Plus,
	RotateCcw,
	SquareTerminal,
	X,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
	AlertDialog,
	AlertDialogAction,
	AlertDialogCancel,
	AlertDialogContent,
	AlertDialogDescription,
	AlertDialogFooter,
	AlertDialogHeader,
	AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Input } from "@/components/ui/input";
import { toast } from "@/hooks/use-toast";
import { desktopClient } from "@/lib/desktop-client";
import { cn } from "@/lib/utils";

type TerminalState = "starting" | "running" | "exited" | "failed" | "cancelled";
type TerminalSession = {
	processId: string;
	state: TerminalState;
	pid: number | null;
	executable: string;
	cwd: string;
	startedAtMs: number;
	exitCode?: number | null;
	latestCursor: number;
	droppedOutputBytes: number;
	recoveredAfterRestart?: boolean;
	label?: string;
};
type TerminalRead = {
	session: TerminalSession;
	chunks: Array<{ cursor: number; stream: "stdout" | "stderr"; text: string }>;
	nextCursor: number;
	truncated: boolean;
	droppedOutputBytes: number;
};

type TerminalBuffer = { cursor: number; text: string };

const ESC = String.fromCharCode(27);
const BEL = String.fromCharCode(7);
const ANSI_PATTERN = new RegExp(
	`${ESC}(?:[@-_][0-?]*[ -/]*[@-~]|\\][^${BEL}]*(?:${BEL}|${ESC}\\\\))`,
	"g",
);

function cleanTerminalText(value: string): string {
	return value.replace(ANSI_PATTERN, "").replace(/\r(?!\n)/g, "");
}

export function WorkspaceTerminal({
	cwd,
	environmentId,
}: {
	cwd?: string;
	environmentId: string;
}) {
	const [sessions, setSessions] = useState<TerminalSession[]>([]);
	const [activeId, setActiveId] = useState<string | null>(null);
	const [buffers, setBuffers] = useState<Record<string, TerminalBuffer>>({});
	const [command, setCommand] = useState("");
	const [profile, setProfile] = useState("default");
	const [confirmStart, setConfirmStart] = useState(false);
	const [starting, setStarting] = useState(false);
	const outputRef = useRef<HTMLPreElement | null>(null);
	const cursorRef = useRef<Record<string, number>>({});

	const invokeArgs = useMemo(
		() => ({ environmentId, ...(cwd?.trim() ? { cwd } : {}) }),
		[cwd, environmentId],
	);
	const active =
		sessions.find((session) => session.processId === activeId) ?? null;
	const activeBuffer = activeId ? buffers[activeId] : undefined;

	const refreshSessions = useCallback(async () => {
		try {
			const next = await desktopClient.invoke<TerminalSession[]>(
				"workspace_terminal_list",
				invokeArgs,
			);
			setSessions(next);
			setActiveId((current) =>
				current && next.some((item) => item.processId === current)
					? current
					: (next.at(-1)?.processId ?? null),
			);
		} catch (error) {
			toast({
				variant: "destructive",
				title: "Could not load terminal sessions",
				description:
					error instanceof Error
						? error.message
						: "Terminal service is unavailable.",
			});
		}
	}, [invokeArgs]);

	useEffect(() => {
		void refreshSessions();
	}, [refreshSessions]);
	useEffect(() => {
		const timer = window.setInterval(() => void refreshSessions(), 2_000);
		return () => window.clearInterval(timer);
	}, [refreshSessions]);

	useEffect(() => {
		if (!activeId) return;
		let cancelled = false;
		const read = async () => {
			const cursor = cursorRef.current[activeId] ?? 0;
			try {
				const result = await desktopClient.invoke<TerminalRead>(
					"workspace_terminal_read",
					{ ...invokeArgs, processId: activeId, cursor },
				);
				if (cancelled) return;
				cursorRef.current[activeId] = result.nextCursor;
				setSessions((previous) =>
					previous.map((item) =>
						item.processId === result.session.processId ? result.session : item,
					),
				);
				setBuffers((previous) => ({
					...previous,
					[activeId]: {
						cursor: result.nextCursor,
						text: `${result.truncated && cursor === 0 ? "[Earlier output was truncated]\n" : ""}${previous[activeId]?.text ?? ""}${cleanTerminalText(result.chunks.map((chunk) => chunk.text).join(""))}`.slice(
							-300_000,
						),
					},
				}));
			} catch {}
		};
		void read();
		const timer = window.setInterval(() => void read(), 500);
		return () => {
			cancelled = true;
			window.clearInterval(timer);
		};
	}, [activeId, invokeArgs]);

	useEffect(() => {
		if (outputRef.current)
			outputRef.current.scrollTop = outputRef.current.scrollHeight;
	});

	const start = async () => {
		setStarting(true);
		try {
			const session = await desktopClient.invoke<TerminalSession>(
				"workspace_terminal_start",
				{
					...invokeArgs,
					profile,
					confirmFullAccess: true,
					columns: 120,
					rows: 32,
				},
			);
			setSessions((previous) => [...previous, session]);
			setActiveId(session.processId);
			setBuffers((previous) => ({
				...previous,
				[session.processId]: { cursor: 0, text: "" },
			}));
		} catch (error) {
			toast({
				variant: "destructive",
				title: "Could not start terminal",
				description:
					error instanceof Error ? error.message : "Terminal start failed.",
			});
		} finally {
			setStarting(false);
		}
	};

	const send = async () => {
		if (!active || active.state !== "running" || !command) return;
		const value = command;
		setCommand("");
		try {
			await desktopClient.invoke("workspace_terminal_write", {
				...invokeArgs,
				processId: active.processId,
				input: `${value}\r`,
			});
		} catch (error) {
			toast({
				variant: "destructive",
				title: "Could not write to terminal",
				description: error instanceof Error ? error.message : "Input failed.",
			});
		}
	};

	const signal = async (kind: "interrupt" | "terminate" | "kill") => {
		if (!active) return;
		try {
			await desktopClient.invoke("workspace_terminal_signal", {
				...invokeArgs,
				processId: active.processId,
				signal: kind,
			});
			await refreshSessions();
		} catch (error) {
			toast({
				variant: "destructive",
				title: "Could not control process",
				description: error instanceof Error ? error.message : "Signal failed.",
			});
		}
	};

	return (
		<div className="flex h-full min-h-0 flex-col bg-[#0d0f12] text-zinc-100">
			<div className="flex shrink-0 items-center gap-2 border-b border-white/10 px-3 py-2">
				<select
					aria-label="Terminal profile"
					className="h-8 rounded-md border border-white/10 bg-white/5 px-2 text-xs"
					onChange={(event) => setProfile(event.target.value)}
					value={profile}
				>
					<option value="default">Default shell</option>
					<option value="cmd">Command Prompt</option>
					<option value="wsl">WSL</option>
					<option value="zsh">zsh</option>
				</select>
				<button
					className="flex h-8 items-center gap-1.5 rounded-md bg-white/10 px-2.5 text-xs hover:bg-white/15 disabled:opacity-50"
					disabled={starting}
					onClick={() => setConfirmStart(true)}
					type="button"
				>
					{starting ? (
						<Loader2 className="h-3.5 w-3.5 animate-spin" />
					) : (
						<Plus className="h-3.5 w-3.5" />
					)}
					New terminal
				</button>
				<span className="ml-auto text-[10px] text-zinc-500">
					Host terminal · secret-redacted output
				</span>
			</div>
			<div className="flex min-h-0 flex-1">
				<aside className="w-48 shrink-0 overflow-auto border-r border-white/10 p-2">
					{sessions.length === 0 ? (
						<p className="p-2 text-xs text-zinc-500">No terminal sessions.</p>
					) : (
						sessions.map((session, index) => (
							<button
								className={cn(
									"mb-1 flex w-full items-center gap-2 rounded-md px-2 py-2 text-left text-xs",
									activeId === session.processId
										? "bg-white/10"
										: "hover:bg-white/5",
								)}
								key={session.processId}
								onClick={() => setActiveId(session.processId)}
								type="button"
							>
								<SquareTerminal className="h-3.5 w-3.5" />
								<span className="min-w-0 flex-1 truncate">
									Terminal {index + 1}
								</span>
								<span
									className={cn(
										"h-1.5 w-1.5 rounded-full",
										session.state === "running"
											? "bg-emerald-400"
											: session.state === "failed"
												? "bg-red-400"
												: "bg-zinc-500",
									)}
								/>
							</button>
						))
					)}
				</aside>
				<div className="flex min-w-0 flex-1 flex-col">
					<div className="flex h-9 shrink-0 items-center gap-2 border-b border-white/10 px-3 text-[11px] text-zinc-400">
						{active ? (
							<>
								<span>PID {active.pid ?? "—"}</span>
								<span>·</span>
								<span className="min-w-0 truncate">{active.cwd}</span>
								<span className="ml-auto capitalize">
									{active.state}
									{active.exitCode !== undefined
										? ` · exit ${active.exitCode ?? "signal"}`
										: ""}
								</span>
								{active.state === "running" && (
									<>
										<button
											aria-label="Interrupt terminal"
											className="rounded p-1 hover:bg-white/10"
											onClick={() => void signal("interrupt")}
											title="Interrupt"
											type="button"
										>
											<CircleStop className="h-3.5 w-3.5" />
										</button>
										<button
											aria-label="Terminate terminal"
											className="rounded p-1 hover:bg-red-500/20 hover:text-red-300"
											onClick={() => void signal("terminate")}
											title="Terminate"
											type="button"
										>
											<X className="h-3.5 w-3.5" />
										</button>
									</>
								)}
							</>
						) : (
							<span>Select or start a terminal.</span>
						)}
					</div>
					<pre
						className="min-h-0 flex-1 overflow-auto whitespace-pre-wrap break-words p-3 font-mono text-xs leading-5 text-zinc-200"
						ref={outputRef}
					>
						{activeBuffer?.text ||
							(active
								? "Waiting for output…"
								: "Start a terminal to run interactive commands.")}
					</pre>
					<div className="flex shrink-0 items-center gap-2 border-t border-white/10 p-2">
						<span className="font-mono text-xs text-emerald-400">›</span>
						<Input
							aria-label="Terminal command"
							autoComplete="off"
							className="h-8 border-0 bg-transparent font-mono text-xs text-zinc-100 focus-visible:ring-0"
							disabled={!active || active.state !== "running"}
							onChange={(event) => setCommand(event.target.value)}
							onKeyDown={(event) => {
								if (event.key === "Enter") {
									event.preventDefault();
									void send();
								}
							}}
							placeholder={
								active?.state === "running"
									? "Type a command and press Enter"
									: "Terminal is not running"
							}
							value={command}
						/>
						<button
							aria-label="Run terminal command"
							className="rounded-md bg-white/10 p-2 hover:bg-white/15 disabled:opacity-30"
							disabled={!active || active.state !== "running" || !command}
							onClick={() => void send()}
							type="button"
						>
							<Play className="h-3.5 w-3.5" />
						</button>
					</div>
				</div>
			</div>
			<AlertDialog onOpenChange={setConfirmStart} open={confirmStart}>
				<AlertDialogContent>
					<AlertDialogHeader>
						<AlertDialogTitle>Start a host terminal?</AlertDialogTitle>
						<AlertDialogDescription>
							This terminal runs commands directly on your computer with the
							active workspace as its working directory. It is not an
							operating-system sandbox. Review commands before running untrusted
							files.
						</AlertDialogDescription>
					</AlertDialogHeader>
					<AlertDialogFooter>
						<AlertDialogCancel>Cancel</AlertDialogCancel>
						<AlertDialogAction onClick={() => void start()}>
							<RotateCcw className="mr-2 h-4 w-4" />
							Start terminal
						</AlertDialogAction>
					</AlertDialogFooter>
				</AlertDialogContent>
			</AlertDialog>
		</div>
	);
}
