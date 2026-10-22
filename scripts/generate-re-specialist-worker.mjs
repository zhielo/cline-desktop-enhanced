import {readFile,writeFile} from 'node:fs/promises';
const input=new URL('../sdk/packages/core/scripts/re-specialist-worker.py',import.meta.url);
const output=new URL('../sdk/packages/core/src/extensions/tools/executors/re-specialist-worker.ts',import.meta.url);
const expected='// Generated from scripts/re-specialist-worker.py; parity is tested.\nexport const RE_SPECIALIST_WORKER = '+JSON.stringify(await readFile(input,'utf8'))+';\n';
if(process.argv.includes('--check')) {if(await readFile(output,'utf8')!==expected)throw new Error('Specialist worker is stale; regenerate it');} else await writeFile(output,expected);
