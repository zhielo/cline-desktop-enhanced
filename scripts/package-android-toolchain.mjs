/** CI-only provisioning. No installed operation downloads software or accepts target build scripts. */
import {createHash} from "node:crypto";
import {readFile,writeFile,mkdir,rm,readdir,copyFile,chmod} from "node:fs/promises";
import {execFileSync} from "node:child_process";
import path from "node:path";
import {fileURLToPath} from "node:url";
const repo=path.resolve(path.dirname(fileURLToPath(import.meta.url)),"..");
const lock=JSON.parse(await readFile(path.join(repo,"scripts/android-toolchain.lock.json"),"utf8"));
const root=path.join(repo,"apps/examples/desktop-app/src-tauri/resources/android-toolchain");
const temporary=path.join(process.env.RUNNER_TEMP||"/tmp","cline-android-toolchain");
await rm(root,{recursive:true,force:true});await mkdir(root,{recursive:true});await mkdir(temporary,{recursive:true});
async function download(url,digest,name){
 const file=path.join(temporary,name);let bytes;
 try{bytes=await readFile(file);}catch{}
 if(!bytes||createHash("sha256").update(bytes).digest("hex")!==digest){
  const response=await fetch(url,{signal:AbortSignal.timeout(180000)});if(!response.ok)throw new Error(`Download failed: ${name} (${response.status})`);
  bytes=Buffer.from(await response.arrayBuffer());await writeFile(file,bytes);
 }
 if(createHash("sha256").update(bytes).digest("hex")!==digest)throw new Error(`Pinned digest mismatch: ${name}`);
 return file;
}
async function extract(zip,destination){
 await mkdir(destination,{recursive:true});
 if(process.platform==="win32") execFileSync("powershell.exe",["-NoProfile","-NonInteractive","-Command",`Expand-Archive -LiteralPath '${zip.replaceAll("'","''")}' -DestinationPath '${destination.replaceAll("'","''")}' -Force`],{stdio:"inherit",timeout:180000});
 else execFileSync("unzip",["-q",zip,"-d",destination],{timeout:180000});
}
for(const asset of lock.assets){
 const file=await download(asset.url,asset.sha256,asset.id+(asset.kind==="zip"?".zip":".jar"));
 const destination=path.join(root,asset.file);
 if(asset.kind!=="zip"){await mkdir(path.dirname(destination),{recursive:true});await copyFile(file,destination);continue;}
 if(asset.id==="jre"&&process.platform!=="win32"){
  const tar=await download(lock.linuxJava.url,lock.linuxJava.sha256,"jre-linux.tar.gz");await mkdir(destination,{recursive:true});execFileSync("tar",["-xzf",tar,"--strip-components=1","-C",destination],{timeout:120000});continue;
 }
 if(asset.id==="jre"||asset.id==="build-tools"){
  const staging=path.join(temporary,asset.id+"-unpack");await rm(staging,{recursive:true,force:true});await extract(file,staging);
  const directories=(await readdir(staging,{withFileTypes:true})).filter(e=>e.isDirectory());if(directories.length!==1)throw new Error("Ambiguous archive root");
  const {cp}=await import("node:fs/promises");
  const source=path.join(staging,directories[0].name);
  if(asset.id==="build-tools"){
   await mkdir(path.join(destination,"lib"),{recursive:true});
   for(const name of ["aapt2.exe","zipalign.exe","dexdump.exe","NOTICE.txt","source.properties"]){await copyFile(path.join(source,name),path.join(destination,name));}
   await copyFile(path.join(source,"lib/apksigner.jar"),path.join(destination,"lib/apksigner.jar"));
   for(const name of await readdir(source))if(name.endsWith(".dll"))await copyFile(path.join(source,name),path.join(destination,name));
  }else await cp(source,destination,{recursive:true});
 }else await extract(file,destination);
}
for(const notice of lock.notices){const file=await download(notice.url,notice.sha256,notice.id+"-LICENSE.txt");await mkdir(path.join(root,"notices"),{recursive:true});await copyFile(file,path.join(root,"notices",notice.id+"-LICENSE.txt"));}
await copyFile(path.join(repo,"scripts/android-toolchain.lock.json"),path.join(root,"tools.lock.json"));
const launcher=path.join(root,"launcher");await mkdir(launcher,{recursive:true});
await copyFile(path.join(repo,"scripts/android-launcher/ClineAndroidLauncher.java"),path.join(launcher,"ClineAndroidLauncher.java"));
// Compilation is CI-only. Installed operations need only the pinned JRE.
const compiler=await download(lock.buildCompiler.url,lock.buildCompiler.sha256,"ecj.jar");
execFileSync(path.join(root,"jre/bin",process.platform==="win32"?"java.exe":"java"),["-jar",compiler,"-17","-encoding","UTF-8","-d",launcher,path.join(launcher,"ClineAndroidLauncher.java")],{stdio:"inherit",timeout:60000});
const files={};async function inventory(dir){for(const item of (await readdir(dir,{withFileTypes:true})).sort((a,b)=>a.name.localeCompare(b.name))){const file=path.join(dir,item.name);if(item.isSymbolicLink()){const {realpath}=await import("node:fs/promises");const actual=await realpath(file);if(!actual.startsWith(root+path.sep))throw new Error("Archive link escaped pack");const bytes=await readFile(actual);await rm(file);await writeFile(file,bytes);files[path.relative(root,file).split(path.sep).join("/")]=createHash("sha256").update(bytes).digest("hex");continue;}if(item.isDirectory())await inventory(file);else files[path.relative(root,file).split(path.sep).join("/")]=createHash("sha256").update(await readFile(file)).digest("hex");}}
await inventory(root);await writeFile(path.join(root,"manifest.json"),JSON.stringify({schemaVersion:1,profile:lock.profile,files},null,2)+"\n");
console.log("Pinned Android toolchain packaged; owned round-trip acceptance must pass separately.");
