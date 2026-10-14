import { createReadStream } from "node:fs";
import { createHash } from "node:crypto";
import { readFile, writeFile, readdir, lstat } from "node:fs/promises";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
async function digest(file) { const hash=createHash("sha256");for await(const chunk of createReadStream(file))hash.update(chunk);return hash.digest("hex"); }
export async function wheelhouseManifest(root, requirements) {
  const names = (await readdir(root)).filter(n => n !== "manifest.json").sort();
  if (!names.length || names.length > 300) throw new Error("Wheel inventory budget");
  let total = 0; const wheels = [];
  for (const name of names) {
    if (!/^[a-zA-Z0-9_.+!-]+\.whl$/.test(name)) throw new Error("Unexpected wheelhouse entry");
    const file = join(root, name), stat = await lstat(file);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 300 * 1024 * 1024 || (total += stat.size) > 2 * 1024 * 1024 * 1024) throw new Error("Wheel inventory bounds");
    wheels.push({ name, bytes: stat.size, sha256: await digest(file) });
  }
  return { schemaVersion: 1, requirementsSha256: await digest(requirements), wheels };
}
export async function verifyWheelhouse(root, requirements) {
  const stat = await lstat(join(root, "manifest.json")); if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 131072) throw new Error("Invalid wheel manifest");
  const saved = JSON.parse(await readFile(join(root, "manifest.json"), "utf8"));
  const actual = await wheelhouseManifest(root, requirements);
  if (JSON.stringify(saved) !== JSON.stringify(actual)) throw new Error("Wheel cache integrity or requirements changed; remove this cache entry and rebuild");
  return actual;
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [action, root, requirements] = process.argv.slice(2);
  if (action === "write") await writeFile(join(root, "manifest.json"), JSON.stringify(await wheelhouseManifest(root, requirements)) + "\n");
  else if (action === "verify") await verifyWheelhouse(root, requirements);
  else throw new Error("Expected write or verify");
}
