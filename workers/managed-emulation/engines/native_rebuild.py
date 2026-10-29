"""CI-container-only private unidbg JNI rebuild; no target/emulator execution.

Original Maven bytes remain independently pinned. Only copied guest JAR resources
are replaced, with exact source/patch/output identities retained in the bundle.
This is not a shipping catalog, installer, desktop dependency upgrade or readiness test.
"""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import tarfile
import urllib.request
import zipfile

NAMES = {'jna-sources.jar','unicorn-source.tar.gz','jna-dispatch.c','jna-callback.c',
    'jna-dispatch.h','jna-protect.h','jna-Makefile','bridge-unicorn.c','bridge-unicorn.h',
    'bridge-sample_arm.c','bridge-sample_arm64.c','bridge-khash.h',
    'bridge-com_github_unidbg_arm_backend_unicorn_Unicorn.h',
    'bridge-com_github_unidbg_arm_backend_unicorn_Unicorn_NewHook.h',
    'bridge-com_github_unidbg_arm_backend_unicorn_Unicorn_Tuple.h',
    'bridge-com_github_unidbg_arm_backend_unicorn_Unicorn_UnHook.h'}
ORIGINS = ('https://raw.githubusercontent.com/','https://repo.maven.apache.org/',
           'https://codeload.github.com/')

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, url):
        raise ValueError('Native source redirect refused')

def digest(data):
    return hashlib.sha256(data).hexdigest()

def unique(pairs):
    out={}
    for k,v in pairs:
        if k in out:raise ValueError('Duplicate native input field')
        out[k]=v
    return out

def load(lock):
    v=json.loads(lock.read_bytes(),object_pairs_hook=unique)
    if not isinstance(v,dict) or set(v)!={'schema','scope','files'} or type(v['schema']) is not int or v['schema']!=1 or v['scope']!='development-owned-guest-tests-only':
        raise ValueError('Native input identity')
    if not isinstance(v['files'],list) or len(v['files'])!=len(NAMES):raise ValueError('Native input count')
    seen=set();total=0
    for e in v['files']:
        if not isinstance(e,dict) or set(e)!={'name','url','bytes','sha256'}:raise ValueError('Native input schema')
        if not isinstance(e['name'],str) or e['name'] not in NAMES or e['name'] in seen:raise ValueError('Native input name')
        seen.add(e['name'])
        if not isinstance(e['url'],str) or not e['url'].startswith(ORIGINS) or '?' in e['url'] or '#' in e['url'] or '\\' in e['url']:raise ValueError('Native input URL')
        if type(e['bytes']) is not int or not 0<e['bytes']<=8*1024**2:raise ValueError('Native input bytes')
        if not isinstance(e['sha256'],str) or len(e['sha256'])!=64 or any(c not in '0123456789abcdef' for c in e['sha256']):raise ValueError('Native input digest')
        total+=e['bytes']
    if total>16*1024**2:raise ValueError('Native source aggregate budget')
    return v

def fetch(lock, directory):
    v=load(lock);directory.mkdir(mode=0o700)
    opener=urllib.request.build_opener(NoRedirect())
    for e in v['files']:
        partial=directory/(e['name']+'.partial');h=hashlib.sha256();length=0
        with opener.open(e['url'],timeout=45) as response,partial.open('xb') as stream:
            if response.status!=200:raise ValueError('Native source HTTP status')
            while block:=response.read(min(65536,e['bytes']-length+1)):
                length+=len(block)
                if length>e['bytes']:raise ValueError('Native source overflow')
                stream.write(block);h.update(block)
        if length!=e['bytes'] or h.hexdigest()!=e['sha256']:raise ValueError('Native source identity mismatch')
        partial.rename(directory/e['name'])
    return v

def relative(name):
    p=PurePosixPath(name)
    if not name or p.is_absolute() or any(x in ('','.','..') for x in name.split('/')) or '\\' in name or '\x00' in name:
        raise ValueError('Unsafe native source path')
    return p

def extract_core(archive, root):
    root.mkdir();seen=set();total=0;prefix=None
    with tarfile.open(archive,'r:gz') as source:
        for index,m in enumerate(source):
            if index>=10000:raise ValueError('Native source count')
            parts=relative(m.name.rstrip('/')).parts
            if prefix is None:prefix=parts[0]
            if parts[0]!=prefix or not (m.isdir() or m.isfile()):raise ValueError('Native source member type/root')
            if len(parts)==1:continue
            label=PurePosixPath(*parts[1:]).as_posix()
            if label in seen:raise ValueError('Duplicate native source path')
            seen.add(label);target=root/label
            if m.isdir():target.mkdir(parents=True,exist_ok=True);continue
            total+=m.size
            if m.size>8*1024**2 or total>64*1024**2:raise ValueError('Native source extraction budget')
            target.parent.mkdir(parents=True,exist_ok=True)
            with source.extractfile(m) as stream,target.open('xb') as out:
                data=stream.read(m.size+1)
                if len(data)!=m.size:raise ValueError('Native source length')
                out.write(data)
            target.chmod(0o755 if m.mode&0o111 else 0o644)

def replace_once(source,old,new):
    if source.count(old)!=1:raise ValueError('Native source patch context')
    return source.replace(old,new)

def patch_jna(source):
    # No new JNI call may follow getProperty with an unchecked pending exception.
    return replace_once(source,'  fileEncoding = get_system_property(env, "file.encoding");\n  if (fileEncoding) {',
        '  fileEncoding = get_system_property(env, "file.encoding");\n  if ((*env)->ExceptionCheck(env)) return "file.encoding";\n  if (fileEncoding) {')

def patch_bridge(source):
    source=replace_once(source,'  if (err != UC_ERR_OK) {\n    const char *msg',
        '  if ((*env)->ExceptionCheck(env)) return;\n  if (err != UC_ERR_OK) {\n    const char *msg')
    source=replace_once(source,'    (*env)->ThrowNew(env, clazz, msg);',
        '    if (clazz != NULL) (*env)->ThrowNew(env, clazz, msg);')
    # Check every Java callback before another JNI call. Keep the original Java
    # exception pending, stop native emulation, and let its Java caller receive it.
    import re
    pattern=r'(?m)^(\s*)\(\*env\)->CallVoidMethod\(env, nh->hook, ([^\n]+)\);$'
    matches=list(re.finditer(pattern,source))
    if len(matches)!=8:raise ValueError('Native void callback inventory')
    source=re.sub(pattern,lambda m:m[1]+'if ((*env)->ExceptionCheck(env)) { uc_emu_stop(eng); jni_env_detach(need_detach); return; }\n'+m[0]+'\n'+m[1]+'if ((*env)->ExceptionCheck(env)) uc_emu_stop(eng);',source)
    source=replace_once(source,'  jboolean res = (*env)->CallBooleanMethod',
        '  if ((*env)->ExceptionCheck(env)) { uc_emu_stop(eng); jni_env_detach(need_detach); return false; }\n  jboolean res = (*env)->CallBooleanMethod')
    source=replace_once(source,'  jni_env_detach(need_detach);\n  return res;',
        '  if ((*env)->ExceptionCheck(env)) { uc_emu_stop(eng); res = JNI_FALSE; }\n  jni_env_detach(need_detach);\n  return res;')
    # A callback exception must not be replaced by a backend error lookup.
    source=replace_once(source,'  uc_err err = uc_emu_start(eng, (uint64_t)begin, (uint64_t)until, (uint64_t)timeout, (size_t)count);',
        '  uc_err err = uc_emu_start(eng, (uint64_t)begin, (uint64_t)until, (uint64_t)timeout, (size_t)count);\n  if ((*env)->ExceptionCheck(env)) return;')
    for name in ('onBlock','onCode','onBreak','onRead','onWrite','onInterrupt','onMemEvent'):
        lines=[line for line in source.splitlines() if line.startswith('  '+name+' = (*env)->GetMethodID(')]
        if len(lines)!=1:raise ValueError('Native callback method inventory')
        source=replace_once(source,lines[0],lines[0]+'\n  if ((*env)->ExceptionCheck(env) || '+name+' == NULL) return JNI_ERR;')
    return source

def replace_resource(jar, label, binary):
    # Preserve every other verified JAR entry; no class/resource pruning/fallback.
    if jar.stat().st_size>64*1024**2 or not 0<binary.stat().st_size<=8*1024**2:raise ValueError('Native JAR byte budget')
    pending=jar.with_suffix('.rebuilt');seen=set();count=0;total=0
    with zipfile.ZipFile(jar) as src,zipfile.ZipFile(pending,'x',compression=zipfile.ZIP_DEFLATED) as dst:
        if len(src.infolist())>4096:raise ValueError('Native JAR entry budget')
        for info in src.infolist():
            total+=info.file_size
            if info.file_size>32*1024**2 or total>128*1024**2:raise ValueError('Native JAR extraction budget')
            if info.filename in seen:raise ValueError('Duplicate native JAR resource')
            seen.add(info.filename)
            if info.filename==label:count+=1;data=binary.read_bytes()
            else:data=src.read(info)
            dst.writestr(info,data)
    if count!=1:raise ValueError('Exact native JAR resource required')
    pending.replace(jar)

def build(runtime, work, java_home=Path('/usr/lib/jvm/java-17-openjdk-amd64')):
    """Only called from the disposable builder; compile, never run an emulator."""
    inputs=fetch(Path(__file__).with_name('native-inputs.lock.json'),work)
    core=work/'core';extract_core(work/'unicorn-source.tar.gz',core)
    bridge=work/'bridge';bridge.mkdir();jna=work/'jna';jna.mkdir()
    for e in inputs['files']:
        name=e['name']
        if name.startswith('bridge-'):shutil.copyfile(work/name,bridge/name[7:])
        elif name.startswith('jna-') and name!='jna-sources.jar':shutil.copyfile(work/name,jna/name[4:])
    original_bridge=(bridge/'unicorn.c').read_text();original_jna=(jna/'dispatch.c').read_text()
    (bridge/'unicorn.c').write_text(patch_bridge(original_bridge));(jna/'dispatch.c').write_text(patch_jna(original_jna))
    sources=work/'java';sources.mkdir();classes=work/'classes';classes.mkdir();headers=work/'headers';headers.mkdir()
    count=0;total=0;seen=set()
    with zipfile.ZipFile(work/'jna-sources.jar') as src:
        for info in src.infolist():
            if not info.filename.endswith('.java'):continue
            label=relative(info.filename);count+=1;total+=info.file_size
            if info.filename in seen:raise ValueError('Duplicate JNA source path')
            seen.add(info.filename)
            if count>128 or info.file_size>1024**2 or total>4*1024**2:raise ValueError('JNA Java source budget')
            target=sources/str(label);target.parent.mkdir(parents=True,exist_ok=True)
            text=src.read(info).decode('utf-8')
            with target.open('x') as stream:stream.write(text)
    def run(*args):subprocess.run([str(x) for x in args],check=True,timeout=900)
    run(java_home/'bin/java','com.sun.tools.javac.Main','--release','8','-proc:none','-encoding','UTF-8','-h',headers,'-d',classes,*sorted(sources.rglob('*.java')))
    jna_output=work/'jna-build';jna_output.mkdir()
    run('make','-C',jna,'DYNAMIC_LIBFFI=true','JAVA_HOME='+str(java_home),'BUILD='+str(jna_output),
        'JAVAH='+str(headers),str(jna_output/'libjnidispatch.so'))
    core_build=work/'core-build'
    run('cmake','-S',core,'-B',core_build,'-DCMAKE_BUILD_TYPE=Release','-DCMAKE_POSITION_INDEPENDENT_CODE=ON',
        '-DBUILD_SHARED_LIBS=OFF','-DUNICORN_BUILD_TESTS=OFF','-DUNICORN_INSTALL=OFF','-DUNICORN_ARCH=arm;aarch64')
    run('cmake','--build',core_build,'--parallel','2')
    unicorn_output=work/'libunicorn.so'
    run('cc','-shared','-fPIC','-O2','-DNDEBUG','-I'+str(core/'include'),'-I'+str(java_home/'include'),
        '-I'+str(java_home/'include/linux'),bridge/'unicorn.c',bridge/'sample_arm.c',bridge/'sample_arm64.c',
        core_build/'libunicorn.a','-lm','-lpthread','-lrt','-o',unicorn_output)
    records=[]
    for jar,label,binary in [(runtime/'dependency/jna-5.10.0.jar','com/sun/jna/linux-x86-64/libjnidispatch.so',jna_output/'libjnidispatch.so'),
            (runtime/'dependency/unidbg-unicorn2-0.9.9.jar','natives/linux_64/libunicorn.so',unicorn_output)]:
        old=digest(jar.read_bytes());replace_resource(jar,label,binary)
        records.append({'jar':jar.name,'resource':label,'originalJarSha256':old,'rebuiltJarSha256':digest(jar.read_bytes()),'nativeSha256':digest(binary.read_bytes())})
    record={'schema':1,'scope':'development-owned-guest-tests-only','sourceInputs':inputs,
        'patchedBridgeSha256':digest((bridge/'unicorn.c').read_bytes()),'patchedJnaSha256':digest((jna/'dispatch.c').read_bytes()),
        'resources':records,'emulatorExecutedDuringBuild':False,'engineReadiness':'not-tested'}
    (runtime/'native-build.json').write_text(json.dumps(record,sort_keys=True,separators=(',',':'))+'\n')
