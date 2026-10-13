import {spawnSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {mkdirSync,readFileSync,writeFileSync,readdirSync} from 'node:fs';
import {resolve,join} from 'node:path';
import {performance} from 'node:perf_hooks';
import {cpus,platform,release} from 'node:os';
const options=Object.fromEntries(process.argv.slice(2).map((v,i,a)=>v.startsWith('--')?[v.slice(2),a[i+1]]:[]).filter(a=>a.length));
const worker=resolve(options['cline-worker']??''),rea=resolve(options['rea-cli']??''),out=resolve(options.out??'.cline-benchmark');
if(!options['cline-worker']||!options['rea-cli'])throw new Error('--cline-worker and --rea-cli absolute executable paths are required');
const packageJson=JSON.parse(readFileSync(resolve(rea,'../../package.json'),'utf8'));
if(packageJson.name!=='rea-agents'||packageJson.version!=='6.4.0')throw new Error('This grader is pinned to rea-agents 6.4.0 only');
const sha=v=>createHash('sha256').update(v).digest('hex');
const corpus=[
 {id:'electron',files:{'main.cjs':`const {ipcMain}=require('electron');ipcMain.handle('owned:add',(e,a,b)=>a+b);const host='https://owned.invalid';function route(h){return h+'/fixture';}fetch(route(host));\n`,'preload.cjs':`const {contextBridge,ipcRenderer}=require('electron');contextBridge.exposeInMainWorld('owned',{add:(a,b)=>ipcRenderer.invoke('owned:add',a,b)});\n`,'renderer.js':'window.owned.add(1,2);\n'},checks:['ipc-channel','ipc-handler','preload-member','computed-request']},
 {id:'modules',files:{'config.ts':`export const base='https://owned.invalid';\n`,'index.ts':`import {base} from './config';function route(h){return h+'/module';}fetch(route(base));\n`},checks:['module-import','computed-module-request']},
 {id:'preload-alias',files:{'preload.cjs':`const {contextBridge,ipcRenderer}=require('electron');const read=async(x)=>await ipcRenderer.invoke('owned:read',x);contextBridge.exposeInMainWorld('owned',{read});\n`,'renderer.js':'window.owned.read(1);\n'},checks:['aliased-preload-member','ipc-read-channel']},
 {id:'lifecycle',files:{'index.cjs':`const fs=require('node:fs'),cp=require('node:child_process');fs.writeFileSync('NEVER_CREATE_THIS_FILE','owned');const timer=setTimeout(()=>{},10);clearTimeout(timer);cp.spawn('owned-never-launch',[]);fetch('https://owned.invalid/literal');\n`},checks:['literal-request','timer-lifecycle','child-process-boundary','resource-lifecycle']},
];
mkdirSync(out,{recursive:true});const home=join(out,'empty-home');mkdirSync(home,{recursive:true});
const env={PATH:process.env.PATH??'',HOME:home,USERPROFILE:home,LANG:'C.UTF-8',...(process.env.SystemRoot?{SystemRoot:process.env.SystemRoot}:{})};
function gradeCline(doc) {
 const f=doc.facts??[],kind=(k,v)=>f.some(x=>x.kind===k&&(v===undefined||x.value===v));
 const member=(name,channel)=>f.some(x=>x.kind==='preload-member'&&(()=>{try{const v=JSON.parse(x.value);return v.path?.includes(name)&&(channel===undefined||v.channel===channel);}catch{return false;}})());
 return {'ipc-channel':kind('ipc-send','owned:add'),'ipc-handler':kind('ipc-handler','owned:add'),'preload-member':member('add'),
 'computed-request':kind('resolved-endpoint','https://owned.invalid/fixture'),'module-import':f.some(x=>x.kind==='import'&&x.value.includes('./config')),
 'computed-module-request':kind('resolved-endpoint','https://owned.invalid/module'),'aliased-preload-member':member('read','owned:read'),'ipc-read-channel':kind('ipc-send','owned:read'),
 'literal-request':kind('resolved-endpoint','https://owned.invalid/literal'),
 'timer-lifecycle':false,'child-process-boundary':false,'resource-lifecycle':false}; // No dedicated first-party families: arbitrary call/literal strings do not count.
}
function gradeRea(doc) {
 if(doc.ok!==true)throw new Error('REA CLI did not return a successful envelope');
 const r=doc.data.normalized_result,nodes=r.graph.nodes,semantic=r.semantic_graph.nodes;
 const observed=(kind,test)=>nodes.some(n=>n.kind===kind&&n.observations?.some(o=>test(o.properties??{})));
 const request=url=>semantic.some(n=>n.kind==='request'&&n.properties?.endpoint===url);
 const family=name=>r.semantic_graph.coverage.families.some(f=>f.family===name&&Number(f.retained_relations??0)>0);
 return {'ipc-channel':observed('ipc-channel',p=>p.channel==='owned:add'&&p.side==='renderer'),'ipc-handler':observed('ipc-handler',p=>p.channel==='owned:add'),
 'preload-member':observed('context-bridge-api',p=>p.api_key==='owned'&&p.members?.includes('add')),'computed-request':request('https://owned.invalid/fixture'),
 'module-import':r.graph.edges.some(e=>e.relation==='imports'&&e.properties?.specifier==='./config'),
 'computed-module-request':request('https://owned.invalid/module'),'aliased-preload-member':observed('context-bridge-api',p=>p.api_key==='owned'&&p.members?.includes('read')),
 'ipc-read-channel':observed('ipc-channel',p=>p.channel==='owned:read'&&p.side==='renderer'),'literal-request':request('https://owned.invalid/literal'),
 'timer-lifecycle':semantic.some(n=>n.kind==='timer')||family('timer'),'child-process-boundary':semantic.some(n=>n.kind==='child-process')||family('child-process'),
 'resource-lifecycle':semantic.some(n=>n.kind==='resource')||family('resource-lifecycle')};
}
const runs=[];for(const c of corpus){const dir=join(out,'fixtures',c.id);mkdirSync(dir,{recursive:true});
 const files={...c.files,'package.json':JSON.stringify({name:`owned-${c.id}`,version:'1.0.0',main:Object.keys(c.files)[0]})+'\n'};
 for(const [name,bytes]of Object.entries(files))writeFileSync(join(dir,name),bytes);
 writeFileSync(join(dir,'fixture-manifest.json'),JSON.stringify(Object.fromEntries(Object.entries(files).map(([n,b])=>[n,sha(b)]))));
 // fixture-manifest.json is inert; both see the identical directory, with explicit unknown input role if applicable.
 for(let repetition=0;repetition<3;repetition++)for(const engine of repetition%2?['rea','cline']:['cline','rea']){
  const start=performance.now();const result=spawnSync(engine==='rea'?process.execPath:worker,engine==='rea'?[rea,'analyze-javascript-application',dir,'--format','json','--full-output','--analysis-timeout-ms','60000','--max-heap-mb','256']:[],{cwd:out,env,input:engine==='cline'?JSON.stringify({workspace:dir,input:{target:'.'}}):undefined,encoding:'utf8',timeout:65000,maxBuffer:16*1024*1024});
  const elapsedMs=performance.now()-start;writeFileSync(join(out,`${c.id}-${engine}-${repetition}.json`),result.stdout??'');writeFileSync(join(out,`${c.id}-${engine}-${repetition}.stderr.txt`),result.stderr??'');
  if(result.status!==0||result.error)throw new Error(`${engine}/${c.id} failed; see retained raw evidence`);
  const doc=JSON.parse(result.stdout),graded=engine==='rea'?gradeRea(doc):gradeCline(doc);
  runs.push({fixture:c.id,engine,repetition,elapsedMs,outputBytes:Buffer.byteLength(result.stdout),stdoutSha256:sha(result.stdout),checks:Object.fromEntries(c.checks.map(k=>[k,graded[k]])),profile:engine==='rea'?'rea-agents/6.4.0':doc.profile});
 }
 if(readdirSync(out).includes('NEVER_CREATE_THIS_FILE')||readdirSync(dir).includes('NEVER_CREATE_THIS_FILE'))throw new Error('Static analyzer executed an owned target');
}
const report={schemaVersion:1,scope:'owned JS/Electron static feature-discovery microbenchmark, not whole-product superiority',recordedAt:new Date().toISOString(),
 provenance:{reaPackageVersion:packageJson.version,reaCliSha256:sha(readFileSync(rea)),clineWorkerSha256:sha(readFileSync(worker)),corpusSha256:sha(JSON.stringify(corpus)),node:process.version,os:platform(),kernel:release(),cpu:cpus()[0]?.model,limits:{wallMs:65000,reaSourceHeapMb:256,repetitions:3,cline:'production fixed worker budgets; not identical memory internals'},setupExcluded:true},
 limitations:['Small owned corpus, not representative all-target accuracy, false-positive rate or tool parity. Twelve explicit feature-discovery checks only; dedicated semantic-family absence in Cline is not guessed from string matches.','Cold process startup plus analysis/end-to-end JSON output. Different shipped runtimes (compiled Bun worker vs Node CLI) and default extractors; same target bytes and wall deadline, not equal internal heap budgets.','No native decompiler, managed assembly, GUI/device, active execution or LLM benchmark in this comparison. No superiority claim.'],runs};
writeFileSync(join(out,'report.json'),JSON.stringify(report,null,2)+'\n');console.log(JSON.stringify({scope:report.scope,runs:runs.length,report:join(out,'report.json')}));
