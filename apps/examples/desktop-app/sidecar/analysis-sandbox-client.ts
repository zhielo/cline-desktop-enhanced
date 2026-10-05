import {z} from "zod";
import { createHash, createPublicKey, randomBytes, verify } from "node:crypto";

export type AnalysisSandboxManifest = {
	workerId: string;
	version: string;
	protocol: "cline-analysis-worker/v1";
	isolation: "hyper-v" | "windows-sandbox" | "remote-vm";
	ephemeralSnapshots: boolean;
	networkModes: Array<"disabled" | "recorded">;
	maxArtifactBytes: number;
	issuedAt: string;
	expiresAt: string;
 operations?: string[];
};

export type AnalysisSandboxHealth = {
	configured: boolean;
	ready: boolean;
	endpoint?: string;
	error?: string;
	manifest?: AnalysisSandboxManifest;
};

type FetchLike = (
	input: string | URL | Request,
	init?: RequestInit,
) => Promise<Response>;

function configuration() {
	const endpoint = process.env.CLINE_ANALYSIS_SANDBOX_WORKER?.trim();
	const publicKey = process.env.CLINE_ANALYSIS_SANDBOX_PUBLIC_KEY?.trim();
	if (!endpoint || !publicKey) return { endpoint, publicKey, valid: false };
	try {
		return {
			endpoint,
			publicKey,
			valid: new URL(endpoint).protocol === "https:" && !new URL(endpoint).username && !new URL(endpoint).password && !new URL(endpoint).hash && !new URL(endpoint).search && new URL(endpoint).pathname === "/",
		};
	} catch {
		return { endpoint, publicKey, valid: false };
	}
}

function validManifest(value: unknown): value is AnalysisSandboxManifest {
	if (!value || typeof value !== "object") return false;
	const manifest = value as AnalysisSandboxManifest;
	return (
		typeof manifest.workerId === "string" && manifest.workerId.length>0 && manifest.workerId.length<=128 &&
		typeof manifest.version === "string" && manifest.version.length>0 && manifest.version.length<=128 &&
		manifest.protocol === "cline-analysis-worker/v1" &&
		["hyper-v", "windows-sandbox", "remote-vm"].includes(manifest.isolation) &&
		manifest.ephemeralSnapshots === true &&
		Array.isArray(manifest.networkModes) &&
		manifest.networkModes.includes("disabled") && manifest.networkModes.every(x=>x === "disabled" || x === "recorded") &&
		Number.isSafeInteger(manifest.maxArtifactBytes) &&
		manifest.maxArtifactBytes > 0 &&
		Date.parse(manifest.issuedAt) >= Date.now()-300_000 && Date.parse(manifest.issuedAt) <= Date.now()+30_000 && Date.parse(manifest.expiresAt) > Date.now() && Date.parse(manifest.expiresAt) <= Date.now()+300_000 && (manifest.operations === undefined || (Array.isArray(manifest.operations) && manifest.operations.length<=32 && manifest.operations.every(x=>typeof x === "string" && x.length<=80)))
	);
}

export async function probeAnalysisSandbox(
	fetchImpl: FetchLike = fetch,
): Promise<AnalysisSandboxHealth> {
	const config = configuration();
	if (!config.endpoint && !config.publicKey) {
		return { configured: false, ready: false };
	}
	if (!config.endpoint || !config.publicKey || !config.valid) {
		return {
			configured: true,
			ready: false,
			error: "Sandbox requires an HTTPS endpoint and pinned public key.",
		};
	}
	const controller = new AbortController();
	const timeout = setTimeout(() => controller.abort(), 5_000);
	try {
		const response = await fetchImpl(
			new URL("/v1/capabilities", config.endpoint),
			{
				method: "GET", redirect:"error",
				headers: { accept: "application/json" },
				signal: controller.signal,
			},
		);
		if (!response.ok) {
			throw new Error(`Worker health returned HTTP ${response.status}`);
		}
		const body = (await boundedWorkerJson(response,65536)) as {
			manifest?: unknown;
			signature?: unknown;
		};
		if (!validManifest(body.manifest) || typeof body.signature !== "string") {
			throw new Error("Worker returned an invalid capability manifest");
		}
		const signatureValid = verify(
			null,
			Buffer.from(JSON.stringify(body.manifest)),
			workerPublicKey(config.publicKey),
			Buffer.from(body.signature, "base64"),
		);
		if (!signatureValid)
			throw new Error("Worker attestation signature is invalid");
		return {
			configured: true,
			ready: true,
			endpoint: config.endpoint,
			manifest: body.manifest,
		};
	} catch (error) {
		return {
			configured: true,
			ready: false,
			endpoint: config.endpoint,
			error: error instanceof Error ? error.message : String(error),
		};
	} finally {
		clearTimeout(timeout);
	}
}

export type AnalysisSandboxSubmission = {
	requestHash: string;
	artifactSha256: string;
	network: "disabled" | "recorded";
	timeoutMs: number;
	maxOutputBytes: number;
};

/**
 * Dynamic execution intentionally remains unavailable until the configured
 * worker passes the signed capability probe. The host never executes a sample.
 */
export async function assertAnalysisSandboxReady(): Promise<AnalysisSandboxManifest> {
	const health = await probeAnalysisSandbox();
	if (!health.ready || !health.manifest) {
		throw new Error(
			health.error ?? "No attested isolated analysis worker is available.",
		);
	}
	return health.manifest;
}

export const RuntimeAnalysisInputSchema=z.object({operation:z.literal("trace_native_region"),target:z.string().min(1).max(4096),symbol:z.string().regex(/^[A-Za-z_][A-Za-z0-9_]{0,127}$/),architecture:z.enum(["x86_64","arm64"]),instruction_limit:z.number().int().min(1).max(100000).default(10000),timeout_ms:z.number().int().min(1000).max(120000).default(60000),worker_endpoint:z.string().url().max(4096).optional(),worker_id:z.string().min(1).max(128).optional(),worker_key_sha256:z.string().regex(/^[a-f0-9]{64}$/).optional()}).strict();
const Receipt=z.object({protocol:z.literal("cline-analysis-job/v1"),workerId:z.string().min(1).max(128),nonce:z.string().regex(/^[a-f0-9]{32}$/),requestHash:z.string().regex(/^[a-f0-9]{64}$/),artifactSha256:z.string().regex(/^[a-f0-9]{64}$/),network:z.literal("disabled"),status:z.enum(["completed","partial","failed"]),engine:z.literal("qbdi"),evidence:z.record(z.string(),z.unknown()),limitations:z.array(z.string().max(1000)).max(100)}).strict();
async function boundedWorkerJson(response:Response,limit:number):Promise<unknown>{if(!response.body)throw new Error("Missing worker body");const reader=response.body.getReader(),chunks:Uint8Array[]=[];let n=0;try{for(;;){const {done,value}=await reader.read();if(done)break;n+=value.byteLength;if(n>limit){await reader.cancel();throw new Error("Worker response byte budget exceeded");}chunks.push(value);}}finally{reader.releaseLock();}return JSON.parse(Buffer.concat(chunks).toString("utf8"));}
function keyHash(key:string){return createHash("sha256").update(workerPublicKey(key).export({type:"spki",format:"der"})).digest("hex");}
export async function bindRuntimeAnalysisRequest(input:z.infer<typeof RuntimeAnalysisInputSchema>,fetchImpl:FetchLike=fetch){const health=await probeAnalysisSandbox(fetchImpl),cfg=configuration();if(!health.ready||!health.manifest||!cfg.endpoint||!cfg.publicKey||!health.manifest.operations?.includes("qbdi-native-trace"))throw new Error("No signed QBDI submission worker configured");return RuntimeAnalysisInputSchema.parse({...input,worker_endpoint:cfg.endpoint,worker_id:health.manifest.workerId,worker_key_sha256:keyHash(cfg.publicKey)});}
/** Transport only: a signed operator claim is not hardware VM attestation. */
export async function submitAnalysisSandbox(input:z.infer<typeof RuntimeAnalysisInputSchema>,artifact:Uint8Array,requestHash:string,signal?:AbortSignal,fetchImpl:FetchLike=fetch){const req=RuntimeAnalysisInputSchema.parse(input);if(!/^[a-f0-9]{64}$/.test(requestHash))throw new Error("Invalid approved request hash");if(signal?.aborted)throw new Error("Cancelled before submission");const health=await probeAnalysisSandbox(fetchImpl),cfg=configuration();if(signal?.aborted)throw new Error("Cancelled before submission");if(!health.ready||!health.manifest||!cfg.publicKey||!cfg.endpoint)throw new Error("No signed isolated worker configured");if(req.worker_endpoint!==cfg.endpoint||req.worker_id!==health.manifest.workerId||req.worker_key_sha256!==keyHash(cfg.publicKey))throw new Error("Worker identity changed since approval");if(!health.manifest.operations?.includes("qbdi-native-trace"))throw new Error("No QBDI submission capability");if(!artifact.byteLength||artifact.byteLength>Math.min(health.manifest.maxArtifactBytes,16*1024*1024))throw new Error("Artifact upload budget exceeded");const artifactSha256=createHash("sha256").update(artifact).digest("hex"),nonce=randomBytes(16).toString("hex"),controller=new AbortController(),abort=()=>controller.abort();signal?.addEventListener("abort",abort,{once:true});if(signal?.aborted)abort();const timer=setTimeout(abort,req.timeout_ms);try{const response=await fetchImpl(new URL("/v1/jobs",cfg.endpoint),{method:"POST",redirect:"error",headers:{"content-type":"application/json",accept:"application/json"},signal:controller.signal,body:JSON.stringify({protocol:"cline-analysis-job/v1",nonce,requestHash,artifactSha256,network:"disabled",operation:req.operation,symbol:req.symbol,architecture:req.architecture,instructionLimit:req.instruction_limit,timeoutMs:req.timeout_ms,maxOutputBytes:1048576,artifactBase64:Buffer.from(artifact).toString("base64")})});if(!response.ok)throw new Error(`Worker HTTP ${response.status}`);const body=await boundedWorkerJson(response,1048576) as {receipt?:unknown,signature?:unknown};if(typeof body.signature!=="string"||body.signature.length>128||!verify(null,Buffer.from(JSON.stringify(body.receipt)),workerPublicKey(cfg.publicKey),Buffer.from(body.signature,"base64")))throw new Error("Worker receipt signature is invalid");const receipt=Receipt.parse(body.receipt);if(receipt.nonce!==nonce||receipt.requestHash!==requestHash||receipt.artifactSha256!==artifactSha256||receipt.workerId!==health.manifest.workerId)throw new Error("Receipt does not bind approved job");return receipt;}finally{clearTimeout(timer);signal?.removeEventListener("abort",abort);}}

function workerPublicKey(pem:string){const key=createPublicKey(pem);if(key.asymmetricKeyType!=="ed25519")throw new Error("Worker requires an Ed25519 key");return key;}
