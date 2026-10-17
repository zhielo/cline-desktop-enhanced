import { z } from "zod";
/** A read-only plan, never authority to attach, resume, evaluate or launch. */
export const RuntimeObservationOptionsSchema = z.object({
 backend: z.literal("node-inspector"),
 pid: z.number().int().positive().max(4294967295),
 processToken: z.string().min(1).max(300),
 endpoint: z.string().max(2048),
 durationMs: z.number().int().min(200).max(5000).default(1000),
 captureConsole: z.boolean().default(false),
}).strict();
export const RuntimeObservationPlanSchema = RuntimeObservationOptionsSchema.extend({
 expected_sha256: z.string().regex(/^[a-f0-9]{64}$/),
}).strict();
