"""Fixed owned fixtures ONLY, inside the disposable offline development guest.

No HTTP worker, arbitrary target, script, classpath, JNI stub or host path input.
A passed fixture is not installed-app readiness or containment attestation.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile

ROOT = Path('/opt/cline-engine')
ARCHES = {'qiling': ['x86_64','arm32','arm64'], 'unidbg':['arm32','arm64'], 'rnidbg':['arm64'], 'speakeasy':['x86_64']}


def unique(pairs):
    result = {}
    for key,value in pairs:
        if key in result:
            raise ValueError('Duplicate owned evidence field')
        result[key] = value
    return result


def verify_bundle():
    raw = (ROOT/'bundle.json').read_bytes()
    if not 1 <= len(raw) <= 4*1024**2:
        raise ValueError('Bundle manifest budget')
    value = json.loads(raw, object_pairs_hook=unique)
    if not isinstance(value,dict) or set(value) != {'schema','engine','scope','files'} or type(value['schema']) is not int or value['schema'] != 1 or value['scope'] != 'development-owned-guest-tests-only' or value['engine'] not in ARCHES:
        raise ValueError('Owned bundle identity')
    if not isinstance(value['files'],dict) or (ROOT/'engine').read_text() != value['engine']+'\n' or not 1 <= len(value['files']) <= 20_000:
        raise ValueError('Owned bundle identity/count')
    observed = {p.relative_to(ROOT).as_posix() for p in ROOT.rglob('*') if p.is_symlink() or p.is_file()}
    if observed != set(value['files']) | {'bundle.json'}:
        raise ValueError('Unsealed runtime file')
    total = 0
    for label, entry in value['files'].items():
        if not isinstance(label,str) or not label or label.startswith('/') or any(p in ('','..','.') for p in label.split('/')) or '\\' in label:
            raise ValueError('Unsafe bundle path')
        path = ROOT/label
        info = path.lstat()
        if entry.get('kind') == 'symlink' and set(entry) == {'kind','target'}:
            if not stat.S_ISLNK(info.st_mode) or os.readlink(path) != entry['target']:
                raise ValueError('Bundle link mismatch')
        elif entry.get('kind') == 'file' and set(entry) == {'kind','size','sha256'}:
            total += info.st_size
            if not stat.S_ISREG(info.st_mode) or info.st_size != entry['size'] or info.st_size > 64*1024**2 or hashlib.sha256(path.read_bytes()).hexdigest() != entry['sha256']:
                raise ValueError('Bundle file mismatch')
        else:
            raise ValueError('Bundle entry type')
    if total > 384*1024**2:
        raise ValueError('Bundle total budget')
    return value['engine'], hashlib.sha256(raw).hexdigest()


def invoke(command, input_bytes=None):
    # Fixed owned adapters only. Guest-wide timeout/poweroff bounds the whole
    # self-test; this command has its own deadline. No target-derived commands.
    return subprocess.run(command, input=input_bytes, stdin=subprocess.DEVNULL if input_bytes is None else None,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=35,
        env={'PATH':'/usr/local/bin:/usr/bin','HOME':'/tmp','LANG':'C.UTF-8','PYTHONDONTWRITEBYTECODE':'1',
             'LD_LIBRARY_PATH':str(ROOT/'syslibs')+':/usr/local/lib', 'CLINE_RE_ISOLATED_WORKER':'disposable-network-disabled'})


def qiling_check():
    sys.path.insert(0,str(ROOT))
    from qiling_runner import run
    checks = 0
    for arch in ARCHES['qiling']:
        label = 'owned-x64' if arch == 'x86_64' else 'owned-linux-'+arch
        fixture = ROOT/'fixtures'/label
        for _ in range(2):
            value = run(fixture,10000,arch)
            if (value['engineVersion'] != '1.4.6' or value['backend'] != 'unicorn-2.1.4' or value['stopReason'] != 'exit' or value['exitCode'] != 7
                    or value['capturedBytes'] != 12 or value['capturedSha256'] != hashlib.sha256(b'cline-owned\n').hexdigest() or not 0 < value['instructionCount'] <= 10000):
                raise ValueError('Owned Qiling result mismatch')
            checks += 1
        denied = ROOT/'fixtures'/('denied-x64' if arch == 'x86_64' else 'denied-linux-'+arch)
        if run(denied,10000,arch)['stopReason'] != 'unsupported-syscall' or run(fixture,1,arch)['stopReason'] == 'exit':
            raise ValueError('Qiling refusal/budget boundary')
        checks += 2
    return checks


def jni_check(engine):
    checks = 0
    for arch in ARCHES[engine]:
        for case in ['positive','denied','budget','missing','fresh']:
            with tempfile.TemporaryDirectory(prefix='owned-jni-') as private:
                root = Path(private); (root/'rootfs').mkdir()
                fixture = ROOT/'fixtures'/('denied-'+arch+'.so' if case == 'denied' else 'owned-'+arch+'.so')
                args = [str(fixture),str(root/'rootfs')]
                if engine == 'unidbg':
                    args.append(arch)
                args += ['jni-int32','com/cline/Owned','missing' if case == 'missing' else 'transform','42',str(root/'result.json'),'1' if case == 'budget' else '10000']
                command = ([str(ROOT/'jre/bin/java'),'--enable-native-access=ALL-UNNAMED','-Duser.home='+private,'-Djava.io.tmpdir='+private,'-Djna.tmpdir='+private,'-XX:-UsePerfData','-Xmx256m','-XX:ReservedCodeCacheSize=64m','-XX:CompressedClassSpaceSize=64m','-cp',str(ROOT/'classes')+':'+str(ROOT/'dependency/*'),'ClineRunner'] if engine == 'unidbg' else [str(ROOT/'jni-runner')])+args
                result = invoke(command)
                if case in ('denied','budget','missing'):
                    if result.returncode == 0 or (root/'result.json').exists() or (case == 'denied' and result.returncode != 76) or (case == 'budget' and result.returncode != 75):
                        raise ValueError('JNI refusal/budget boundary')
                else:
                    if result.returncode:
                        print('CLINE_MANAGED_ENGINE_DIAGNOSTIC_V1 JNI exit='+str(result.returncode)+' '+result.stderr[-4096:].decode(errors='replace'),file=sys.stderr)
                        raise ValueError('Owned JNI execution failed')
                    raw = (root/'result.json').read_bytes()
                    if len(raw)>4096:
                        raise ValueError('Owned JNI execution failed')
                    value = json.loads(raw,object_pairs_hook=unique)
                    if set(value) != {'initialized','returnValue','backend','instructionCount'} or value['initialized'] is not True or value['returnValue'] != 134 or value['backend'] != ('unicorn2' if engine == 'unidbg' else 'pinned-unicorn-fork') or type(value['instructionCount']) is not int or not 0 < value['instructionCount'] <= 10000:
                        raise ValueError('Owned JNI result mismatch')
                checks += 1
    return checks


def speakeasy_check():
    spec = importlib.util.spec_from_file_location('owned_pe',ROOT/'owned_pe.py')
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    import speakeasy
    checks = 0
    with tempfile.TemporaryDirectory(prefix='owned-pe-') as private:
        artifact = Path(private)/'owned.exe'
        for kind,data in [('entry',module.owned_pe()),('api',module.owned_api_pe()),('fresh',module.owned_pe())]:
            artifact.write_bytes(data)
            request = {'artifact':str(artifact),'artifactSha256':hashlib.sha256(data).hexdigest()}
            result = invoke([sys.executable,'-B','-I',str(ROOT/'collector.py')],json.dumps(request).encode())
            if result.returncode or len(result.stdout)>1024*1024:
                raise ValueError('Owned PE collector failed')
            value = json.loads(result.stdout,object_pairs_hook=unique)
            if value.get('status') != 'partial' or value.get('engineVersion') != '1.5.11' or value.get('entrypointCount',0)<1 or value.get('memoryBoundary',{}).get('hard') is not True or (kind=='api' and not any('GetTickCount' in row['api'] for row in value['apiCalls'])):
                raise ValueError('Owned modeled PE evidence mismatch')
            checks += 1
        result = invoke([sys.executable,'-B','-I',str(ROOT/'collector.py')],json.dumps({'artifact':str(artifact),'artifactSha256':'0'*64}).encode())
        if result.returncode == 0 or json.loads(result.stdout).get('status') != 'failed':
            raise ValueError('PE identity refusal boundary')
    return checks+1


def main():
    if sys.platform != 'linux':
        raise ValueError('Owned Linux guest required')
    engine,digest = verify_bundle()
    checks = qiling_check() if engine=='qiling' else speakeasy_check() if engine=='speakeasy' else jni_check(engine)
    if checks != {'qiling':12,'unidbg':10,'rnidbg':5,'speakeasy':4}[engine]:
        raise ValueError('Incomplete owned engine coverage')
    # Rehash AFTER emulation too; bytecode/cache/runtime mutation must not pass.
    if verify_bundle() != (engine,digest):
        raise ValueError('Owned runtime changed')
    print('CLINE_MANAGED_ENGINE_OWNED_V1 '+json.dumps({'schema':1,'engine':engine,'architectures':ARCHES[engine], 'checks':checks,'bundleSha256':digest,'ownedFixtures':'passed','engineReadiness':'not-tested','vmIsolation':'not-attested'},sort_keys=True,separators=(',',':')))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        # This developer-only test runs BEFORE boot credentials, and accepts only
        # checked-in owned fixtures. Bounded diagnostic text never contains a target.
        print('CLINE_MANAGED_ENGINE_FAILED_V1 '+type(error).__name__+': '+str(error)[:400],file=sys.stderr)
        raise SystemExit(1)
