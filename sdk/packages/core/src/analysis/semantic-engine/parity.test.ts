import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { expect, it } from "vitest";
import { analyzeSemanticSources, digestCanonicalValue } from "./engine";

// CI supplies a separately checked-out pinned reference. It is never a production dependency.
const root = process.env.CLINE_SEMANTIC_REFERENCE_ROOT;
const referenceTest = root ? it : it.skip;
referenceTest(
	"matches the pinned upstream file-local graph across owned semantic fixtures",
	async () => {
		const base = resolve(root!);
		const load = async (p: string) =>
			import(/* @vite-ignore */ pathToFileURL(join(base, p)).href);
		const { createJavaScriptSemanticGraphProjection } = await load(
			"src/application/javascript/JavaScriptSemanticGraphBuilder.ts",
		);
		const { analyzeParsedJavaScriptSemantics } = await load(
			"src/domain/javascript/javascriptSemanticAnalysis.ts",
		);
		const { parseJavaScriptSource } = await load(
			"src/domain/javascript/javascriptSourceParser.ts",
		);
		const corpus = [
			"const outer=2; function add(v){return v+outer}; const answer=add(40);",
			"const object={count:1}; object.count=2; const {count}=object;",
			"async function run(v){return await Promise.resolve(v)}; run(1).then(x=>x+1);",
			"const {EventEmitter}=require('events'); const e=new EventEmitter(); const f=()=>42;e.on('ready',f);e.emit('ready');e.off('ready',f);",
			"const t=setTimeout(()=>42,10); clearTimeout(t);",
			"const {spawn}=require('child_process'); const child=spawn('owned',[]); child.on('exit',()=>{});",
			"const host=process.env.HOST||'https://owned.invalid'; fetch(host).then(r=>r.json());",
			"import {ipcRenderer} from 'electron'; ipcRenderer.invoke('owned:add',1);",
			"function require(x){return x};require('electron');",
			"const key=unknown();const object={};object[key]=42;",
			"function broken( {",
			"throw new Error('MUST_NOT_EXECUTE');",
		];
		for (const [index, text] of corpus.entries()) {
			const file = `owned-${index}.js`,
				hash = createHash("sha256").update(text).digest("hex");
			const source = {
				path: file,
				source: text,
				sha256: hash,
				bytes: Buffer.byteLength(text),
			};
			const rootHash = digestCanonicalValue([{ path: file, sha256: hash }]);
			const projection = createJavaScriptSemanticGraphProjection();
			const artifact = {
				path: file,
				container_sha256: rootHash,
				sha256: hash,
				bytes: source.bytes,
				inventory_artifact_id: `art_${hash}`,
				kind: "javascript",
				unpacked: false,
				text: { included: true, value: text },
			};
			const parsed = parseJavaScriptSource(text, file);
			if (parsed === null)
				projection.recordUnavailableFile(
					artifact,
					"Source could not be parsed",
					null,
					"incomplete-module",
				);
			else
				projection.projectFile(
					artifact,
					analyzeParsedJavaScriptSemantics(parsed),
				);
			const original = projection.finish(rootHash, {
				graph_id: `jag_${rootHash}`,
				nodes: [],
			});
			const integrated = await analyzeSemanticSources([source]);
			expect(digestCanonicalValue(integrated), `fixture ${index}`).toBe(
				digestCanonicalValue(original),
			);
		}
		// Check that the reference really contains the expected source, not a substituted implementation.
		const expected = JSON.parse(
			readFileSync(
				new URL("./upstream/PROVENANCE.json", import.meta.url),
				"utf8",
			),
		);
		for (const f of expected.files.filter((f: { path: string }) =>
			f.path.startsWith("src/"),
		)) {
			const hash = createHash("sha256")
				.update(readFileSync(join(base, f.path)))
				.digest("hex");
			expect(hash, f.path).toBe(f.sha256);
		}
	},
	60_000,
);
