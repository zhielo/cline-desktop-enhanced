import { randomUUID } from "node:crypto";
import * as fs from "node:fs/promises";
import * as path from "node:path";

// A successful launcher exit alone is not a Ghidra analysis receipt.
export const GHIDRA_VERIFICATION_SCRIPT = `import ghidra.app.util.headless.HeadlessScript;
import java.io.PrintWriter;
import com.google.gson.JsonObject;
public class ClineVerifyAnalysis extends HeadlessScript {
 protected void run() throws Exception {
  String[] args=getScriptArgs();
  if(args.length!=3 || currentProgram==null) throw new IllegalStateException("Missing owned receipt arguments/program");
  if(monitor.isCancelled() || analysisTimeoutOccurred()) throw new IllegalStateException("Auto-analysis cancelled or incomplete");
  String hash=currentProgram.getExecutableSHA256();
  if(hash==null || !hash.equalsIgnoreCase(args[2])) throw new IllegalStateException("Imported program fingerprint mismatch");
  JsonObject receipt=new JsonObject(); receipt.addProperty("schemaVersion",1);
  receipt.addProperty("attempt",args[1]);receipt.addProperty("inputSha256",hash.toLowerCase());
  receipt.addProperty("javaVersion",System.getProperty("java.version"));receipt.addProperty("javaHome",System.getProperty("java.home"));
  receipt.addProperty("programName",currentProgram.getName());receipt.addProperty("analysisCompleted",true);
  try(PrintWriter out=new PrintWriter(args[0],"UTF-8")){out.println(receipt.toString());}
 }
}
`;

export function ghidraScriptPath(directories: string[]): string {
	const unique = [...new Set(directories)];
	if (unique.some((p) => /[;\0\r\n]/.test(p)))
		throw new Error(
			"Ghidra script directories cannot contain semicolons or control characters",
		);
	return unique.join(";"); // Ghidra uses semicolons on every host, not path.delimiter.
}
export async function prepareGhidraVerification(
	outputDir: string,
	hash: string,
) {
	const script = path.join(outputDir, "ClineVerifyAnalysis.java");
	const receipt = path.join(outputDir, "ghidra-analysis-receipt.json");
	const attempt = randomUUID();
	await fs.rm(receipt, { force: true });
	await fs.rm(script, { force: true });
	await fs.writeFile(script, GHIDRA_VERIFICATION_SCRIPT, {
		mode: 0o600,
		flag: "wx",
	});
	return {
		script,
		receipt,
		attempt,
		args: ["-postScript", path.basename(script), receipt, attempt, hash],
	};
}
export async function verifyGhidraAnalysis(
	project: string,
	verification: { receipt: string; attempt: string },
	hash: string,
) {
	try {
		const projectStat = await fs.lstat(project);
		const repository = await fs.lstat(project.replace(/\.gpr$/, ".rep"));
		const properties = await fs.lstat(
			path.join(project.replace(/\.gpr$/, ".rep"), "project.prp"),
		);
		const receiptStat = await fs.lstat(verification.receipt);
		if (
			!projectStat.isFile() ||
			projectStat.isSymbolicLink() ||
			!properties.isFile() ||
			properties.isSymbolicLink() ||
			properties.size === 0 ||
			!repository.isDirectory() ||
			repository.isSymbolicLink() ||
			!receiptStat.isFile() ||
			receiptStat.isSymbolicLink() ||
			receiptStat.size > 16384
		)
			return false;
		const value = JSON.parse(await fs.readFile(verification.receipt, "utf8"));
		return (
			value.schemaVersion === 1 &&
			value.attempt === verification.attempt &&
			value.inputSha256 === hash &&
			value.analysisCompleted === true &&
			typeof value.programName === "string" &&
			value.programName.length > 0
		);
	} catch {
		return false;
	}
}
