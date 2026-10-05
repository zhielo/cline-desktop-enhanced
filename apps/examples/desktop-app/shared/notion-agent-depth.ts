export const NOTION_AGENT_DEPTH_LIMITS = {
	quick: { files: 25, bytes: 250_000, batchBytes: 80_000 },
	deep: { files: 100, bytes: 1_000_000, batchBytes: 100_000 },
	forensic: { files: 200, bytes: 2_000_000, batchBytes: 125_000 },
} as const;
