import Java from 'frida-java-bridge';
// Fixed hooks. No commands or user-provided JavaScript are accepted.
let captureDex = false;
rpc.exports = { configure(flag) { captureDex = flag === true; } };
let eventCount = 0, captureBytes = 0;
function event(kind, source) { if (eventCount++ < 200) send({kind,source:String(source).slice(0,2048),timestamp:Date.now()}); }
const attached = new Set();
Process.attachModuleObserver({onAdded(module) {
 if (!module.name.includes('libart')) return;
 let inspected = 0;
 for (const symbol of module.enumerateSymbols()) {
  if (++inspected > 100000) { event('jni-symbol-budget',module.name); break; }
  if (!symbol.name.includes('RegisterNatives') || !symbol.name.includes('JNI') || symbol.name.includes('CheckJNI') || attached.has(symbol.address.toString())) continue;
  attached.add(symbol.address.toString());
  Interceptor.attach(symbol.address,{onEnter(args) {
   try {
    const count=args[3].toInt32();if(count<0||count>200)return;
    const className=Java.vm.getEnv().getClassName(args[1]).replace(/\./g,'/');
    const classDescriptor=className.startsWith('[')?className:'L'+className+';';
    for(let i=0;i<count && eventCount++<200;i++){
     const row=args[2].add(i*Process.pointerSize*3),name=row.readPointer().readCString(512),descriptor=row.add(Process.pointerSize).readPointer().readCString(512),address=row.add(Process.pointerSize*2).readPointer(),owner=Process.findModuleByAddress(address);
     if(!name||!descriptor)continue;
     const record={classDescriptor,name,descriptor,addressHex:address.toString(),processId:Process.id,classHandle:args[1].toString(),classLoaderIdentity:'unresolved',timestamp:Date.now(),kind:'worker-observed-registration'};
     if(owner){record.module=owner.path;record.relativeAddress=address.sub(owner.base).toString();}
     send({kind:'registration',record});
    }
   }catch(error){event('jni-registration-unresolved','Supported JNI hook could not resolve this registration');}
  }});
 }
}});
if (Java.available) Java.perform(function(){
 const Base64=Java.use('android.util.Base64');
 function emit(bytes,source){if(!captureDex)return;if(bytes.length>2097152||captureBytes+bytes.length>8388608){event('dex-byte-budget',source);return;}captureBytes+=bytes.length;send({kind:'dex',source:String(source).slice(0,2048),timestamp:Date.now(),base64:String(Base64.encodeToString(bytes,2))});}
 function buffer(value,source){try{const duplicate=value.duplicate(),size=duplicate.remaining();if(size<=0||size>2097152){event('dex-byte-budget',source);return;}const bytes=Java.array('byte',Array(size).fill(0));duplicate.get(bytes);emit(bytes,source);}catch(error){event('dex-buffer-unresolved',source);}}
 try {
  const Memory=Java.use('dalvik.system.InMemoryDexClassLoader');
  for(const overload of Memory.$init.overloads) overload.implementation=function(){const values=Array.from(arguments);if(captureDex){const first=values[0];if(first&&first.duplicate)buffer(first,'InMemoryDexClassLoader');else if(first&&first.length!==undefined)for(let i=0;i<Math.min(first.length,32);i++)buffer(first[i],'InMemoryDexClassLoader['+i+']');}event('in-memory-loader','InMemoryDexClassLoader');return overload.apply(this,values);};
 }catch(error){event('loader-hook-unavailable','InMemoryDexClassLoader');}
 try{
  const Dex=Java.use('dalvik.system.DexClassLoader'),File=Java.use('java.io.File'),Stream=Java.use('java.io.FileInputStream');
  const constructor=Dex.$init.overload('java.lang.String','java.lang.String','java.lang.String','java.lang.ClassLoader');
  constructor.implementation=function(path,optimized,libraries,parent){event('dex-loader',path);if(captureDex)for(const part of String(path).split(':').slice(0,32)){let input=null;try{const size=Number(File.$new(part).length());if(size<112||size>2097152)continue;input=Stream.$new(part);const bytes=Java.array('byte',Array(size).fill(0));let offset=0;while(offset<size){const n=input.read(bytes,offset,size-offset);if(n<=0)break;offset+=n;}if(offset===size)emit(bytes,part);}catch(error){event('loader-file-unresolved',part);}finally{if(input)input.close();}}return constructor.call(this,path,optimized,libraries,parent);};
 }catch(error){event('loader-hook-unavailable','DexClassLoader');}
});
else event('java-runtime-unavailable','No Java loader hooks installed');
