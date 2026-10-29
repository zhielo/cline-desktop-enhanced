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
import selectors
import signal
import time
import subprocess
import sys
import tempfile

ROOT = Path('/opt/cline-engine')
MAX_BUNDLE_BYTES = 384*1024**2
INVOKE_SECONDS = 35
INVOKE_STDOUT_LIMIT = 1024*1024
INVOKE_STDERR_LIMIT = 16*1024
ARCHES = {'qiling': ['x86_64','arm32','arm64'], 'unidbg':['arm32','arm64'], 'rnidbg':['arm64'], 'speakeasy':['x86_64']}


def unique(pairs):
    result = {}
    for key,value in pairs:
        if key in result:
            raise ValueError('Duplicate owned evidence field')
        result[key] = value
    return result


def regular_bytes(path, limit):
    # Check type/size before allocation and pin the descriptor across the read.
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or not 0 <= before.st_size <= limit:
            raise ValueError('Owned file type or byte budget')
        with os.fdopen(descriptor, 'rb', closefd=False) as stream:
            raw = stream.read(limit+1)
        after = os.fstat(descriptor)
        if len(raw) != before.st_size or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise ValueError('Owned file changed while reading')
        return raw
    finally:
        os.close(descriptor)


def verify_bundle():
    raw = regular_bytes(ROOT/'bundle.json', 4*1024**2)
    if not raw:
        raise ValueError('Bundle manifest budget')
    value = json.loads(raw, object_pairs_hook=unique)
    if not isinstance(value,dict) or set(value) != {'schema','engine','scope','files'} or type(value['schema']) is not int or value['schema'] != 1 or value['scope'] != 'development-owned-guest-tests-only' or not isinstance(value['engine'],str) or value['engine'] not in ARCHES:
        raise ValueError('Owned bundle identity')
    if not isinstance(value['files'],dict) or regular_bytes(ROOT/'engine',32) != (value['engine']+'\n').encode() or not 1 <= len(value['files']) <= 20_000:
        raise ValueError('Owned bundle identity/count')
    observed = set()
    count = 0
    for path in ROOT.rglob('*'):
        count += 1
        if count > 40_000:
            raise ValueError('Runtime directory count budget')
        mode = path.lstat().st_mode
        if stat.S_ISLNK(mode) or stat.S_ISREG(mode):
            observed.add(path.relative_to(ROOT).as_posix())
        elif not stat.S_ISDIR(mode):
            raise ValueError('Special runtime file')
    if observed != set(value['files']) | {'bundle.json'}:
        raise ValueError('Unsealed runtime file')
    total = 0
    for label, entry in value['files'].items():
        if not isinstance(label,str) or not label or label.startswith('/') or any(p in ('','..','.') for p in label.split('/')) or '\\' in label or '\x00' in label:
            raise ValueError('Unsafe bundle path')
        if not isinstance(entry,dict):
            raise ValueError('Bundle entry type')
        path = ROOT/label
        info = path.lstat()
        if entry.get('kind') == 'symlink' and set(entry) == {'kind','target'}:
            target = entry['target']
            if not isinstance(target,str) or not target or len(target) > 1024 or '\x00' in target or not stat.S_ISLNK(info.st_mode) or os.readlink(path) != target:
                raise ValueError('Bundle link mismatch')
        elif entry.get('kind') == 'file' and set(entry) == {'kind','size','sha256'}:
            length, digest = entry['size'], entry['sha256']
            if type(length) is not int or not 0 <= length <= 64*1024**2 or not isinstance(digest,str) or len(digest) != 64 or any(c not in '0123456789abcdef' for c in digest):
                raise ValueError('Bundle file schema')
            total += length
            # Enforce aggregate limits BEFORE reading or hashing the next file.
            if total > MAX_BUNDLE_BYTES:
                raise ValueError('Bundle total budget')
            if not stat.S_ISREG(info.st_mode) or info.st_size != length or hashlib.sha256(regular_bytes(path,length)).hexdigest() != digest:
                raise ValueError('Bundle file mismatch')
        else:
            raise ValueError('Bundle entry type')
    return value['engine'], hashlib.sha256(raw).hexdigest()


def invoke(command, input_bytes=None):
    # Only fixed owned adapters run here, before any guest boot credentials.
    # Bound pipe allocation as bytes arrive, not after communicate() allocates.
    if sys.platform != 'linux' or input_bytes is not None and (not isinstance(input_bytes,bytes) or len(input_bytes)>4096):
        raise ValueError('Owned Linux command input budget')
    process = subprocess.Popen(command, stdin=subprocess.DEVNULL if input_bytes is None else subprocess.PIPE,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True, bufsize=0,
        env={'PATH':'/usr/local/bin:/usr/bin','HOME':'/tmp','LANG':'C.UTF-8','PYTHONDONTWRITEBYTECODE':'1',
             'LD_LIBRARY_PATH':str(ROOT/'syslibs')+':/usr/local/lib', 'CLINE_RE_ISOLATED_WORKER':'disposable-network-disabled'})
    output, errors = bytearray(), bytearray()
    deadline = time.monotonic()+INVOKE_SECONDS
    selector = selectors.DefaultSelector()
    try:
        for stream, kind in [(process.stdout,'stdout'),(process.stderr,'stderr')]:
            os.set_blocking(stream.fileno(),False)
            selector.register(stream,selectors.EVENT_READ,kind)
        pending = memoryview(input_bytes or b'')
        if process.stdin:
            if pending:
                os.set_blocking(process.stdin.fileno(),False)
                selector.register(process.stdin,selectors.EVENT_WRITE,'stdin')
            else:
                process.stdin.close()
        while True:
            remaining = deadline-time.monotonic()
            if remaining <= 0:
                raise ValueError('Owned command deadline')
            if not selector.get_map():
                # Observe without reaping: the leader PID remains reserved until
                # its whole process group has been killed in finally below.
                exited = os.waitid(os.P_PID,process.pid,os.WEXITED | os.WNOHANG | os.WNOWAIT)
                if exited is not None:
                    break
                time.sleep(min(remaining,0.01))
                continue
            for key,_ in selector.select(min(remaining,0.2)):
                stream, kind = key.fileobj,key.data
                if kind == 'stdin':
                    try:
                        pending = pending[os.write(stream.fileno(),pending):]
                    except BrokenPipeError:
                        pending = memoryview(b'')
                    except BlockingIOError:
                        continue
                    if not pending:
                        selector.unregister(stream);stream.close()
                    continue
                try:
                    data = os.read(stream.fileno(),65536)
                except BlockingIOError:
                    continue
                if not data:
                    selector.unregister(stream);stream.close();continue
                buffer, limit = (output,INVOKE_STDOUT_LIMIT) if kind == 'stdout' else (errors,INVOKE_STDERR_LIMIT)
                if len(buffer)+len(data)>limit:
                    raise ValueError('Owned command output budget')
                buffer.extend(data)
    finally:
        selector.close()
        # Never poll/reap first: that could let the original process-group ID
        # be reused. This only terminates this fresh owned guest command group.
        try:
            os.killpg(process.pid,signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=5)
        finally:
            for stream in (process.stdin,process.stdout,process.stderr):
                if stream and not stream.closed:
                    stream.close()
    return subprocess.CompletedProcess(command,process.returncode,bytes(output),bytes(errors))


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


def validate_jni_refusal(result, result_path, engine, arch, case):
    # Fixed owned guest checks only, before any private boot credentials. Do not
    # count an OOM, unrelated JVM error or killed runner as a missing-export test.
    contracts = {
        'denied': (76, b'CLINE_UNIDBG_GUARD_V1 76' if engine == 'unidbg' else None),
        'budget': (75, b'CLINE_UNIDBG_GUARD_V1 75' if engine == 'unidbg' else None),
        'missing': ((1, b'java.lang.IllegalArgumentException: Exact static JNI export required')
                    if engine == 'unidbg' else (-signal.SIGABRT, b'exact JNI export missing')),
    }
    if engine not in ('unidbg', 'rnidbg') or arch not in ARCHES[engine] or case not in contracts:
        raise ValueError('Unknown owned JNI refusal profile')
    expected, evidence = contracts[case]
    exists = result_path.exists() or result_path.is_symlink()
    if result.returncode != expected or exists or (evidence is not None and evidence not in result.stderr):
        # Structured bounded diagnostics distinguish the exact engine/profile/
        # scenario and JVM error without printing argv, stdout or result bytes.
        diagnostic = {'engine':engine,'architecture':arch,'case':case,
                      'expectedExit':expected,'observedExit':result.returncode,
                      'resultExists':exists,'stderrBytes':len(result.stderr),
                      'stderrTail':result.stderr[-4096:].decode('utf-8',errors='replace')}
        print('CLINE_MANAGED_JNI_REFUSAL_DIAGNOSTIC_V1 '+json.dumps(diagnostic,sort_keys=True,separators=(',',':')),file=sys.stderr)
        raise ValueError('JNI refusal/budget boundary')


def owned_jvm_failure_evidence(result, private, arch, case):
    """Retain bounded *owned fixture* unexpected-exit evidence before cleanup.

    Includes non-signal fatal exits: exit 1 is not necessarily a Java exception.
    Never used by a target runner or after private boot credentials are supplied.
    No diagnostic makes an unexpected exit or native crash an accepted guard.
    """
    if arch not in ARCHES['unidbg'] or case not in ('positive','denied','budget','missing','fresh'):
        raise ValueError('Unknown owned JVM failure profile')
    expected = {'positive':0,'fresh':0,'denied':76,'budget':75,'missing':1}[case]
    if result.returncode == expected:
        return
    path = private/'hotspot-crash.log'
    report = {'status':'absent'}
    descriptor = None
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            report = {'status':'unsafe-type'}
        elif not 0 < before.st_size <= 1024*1024:
            report = {'status':'byte-budget'}
        else:
            # HotSpot's fatal header and native frame list precede verbose
            # registers/VM options. Keep only a bounded prefix, not the file.
            raw = os.read(descriptor, min(before.st_size, 12288))
            after = os.fstat(descriptor)
            fields = ('st_dev','st_ino','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
            if any(getattr(before,k) != getattr(after,k) for k in fields) or len(raw) != min(before.st_size,12288):
                report = {'status':'changed'}
            else:
                report = {'status':'captured','bytes':before.st_size,
                          'prefix':raw.decode('utf-8',errors='replace')}
    except FileNotFoundError:
        pass
    except OSError:
        report = {'status':'unavailable'}
    finally:
        if descriptor is not None:
            os.close(descriptor)
    value = {'engine':'unidbg','architecture':arch,'case':case,
             'observedExit':result.returncode,'hotspot':report,
             'stdoutBytes':len(result.stdout),
             'stdoutPrefix':result.stdout[:4096].decode('utf-8',errors='replace'),
             'stderrBytes':len(result.stderr),
             'stderrPrefix':result.stderr[:4096].decode('utf-8',errors='replace'),
             'resultExists':(private/'result.json').exists() or (private/'result.json').is_symlink()}
    print('CLINE_MANAGED_OWNED_JVM_FAILURE_V1 '+json.dumps(value,sort_keys=True,separators=(',',':')),file=sys.stderr)


def validate_owned_checked_jni(result, arch, case):
    # HotSpot can warn about invalid JNI usage yet let the process return 0.
    # Fixed public owned fixtures only: warnings are not passed evidence.
    if arch not in ARCHES['unidbg'] or case not in ('positive','denied','budget','missing','fresh'):
        raise ValueError('Unknown owned checked JNI profile')
    markers = (b'WARNING in native method:', b'WARNING: JNI local refs:', b'FATAL ERROR in native method:')
    if any(marker in stream for stream in (result.stdout,result.stderr) for marker in markers):
        value = {'architecture':arch,'case':case,'observedExit':result.returncode,
                 'stdoutBytes':len(result.stdout),'stderrBytes':len(result.stderr),
                 'stdoutPrefix':result.stdout[:4096].decode('utf-8',errors='replace'),
                 'stderrPrefix':result.stderr[:4096].decode('utf-8',errors='replace')}
        print('CLINE_MANAGED_OWNED_CHECKED_JNI_FAILED_V1 '+json.dumps(value,sort_keys=True,separators=(',',':')),file=sys.stderr)
        raise ValueError('Owned checked JNI reported invalid native usage')


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
                command = ([str(ROOT/'jre/bin/java'),'-Xcheck:jni','--enable-native-access=ALL-UNNAMED','-Duser.home='+private,'-Djava.io.tmpdir='+private,'-Djna.tmpdir='+private,'-XX:ErrorFile='+str(root/'hotspot-crash.log'),'-XX:-CreateCoredumpOnCrash','-XX:-UsePerfData','-Xmx256m','-XX:ReservedCodeCacheSize=64m','-XX:CompressedClassSpaceSize=64m','-cp',str(ROOT/'classes')+':'+str(ROOT/'dependency/*'),'ClineRunner'] if engine == 'unidbg' else [str(ROOT/'jni-runner')])+args
                result = invoke(command)
                if engine == 'unidbg':
                    owned_jvm_failure_evidence(result, root, arch, case)
                    validate_owned_checked_jni(result, arch, case)
                if case in ('denied','budget','missing'):
                    validate_jni_refusal(result, root/'result.json', engine, arch, case)
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
    # The fixed entry drops root before importing any engine/native backend.
    spec = importlib.util.spec_from_file_location('cline_engine_entry','/opt/cline/engine_entry.py')
    policy = importlib.util.module_from_spec(spec); spec.loader.exec_module(policy)
    identity = policy.verify_identity()
    engine,digest = verify_bundle()
    checks = qiling_check() if engine=='qiling' else speakeasy_check() if engine=='speakeasy' else jni_check(engine)
    if checks != {'qiling':12,'unidbg':10,'rnidbg':5,'speakeasy':4}[engine]:
        raise ValueError('Incomplete owned engine coverage')
    # Rehash AFTER emulation too; bytecode/cache/runtime mutation must not pass.
    if verify_bundle() != (engine,digest):
        raise ValueError('Owned runtime changed')
    print('CLINE_MANAGED_ENGINE_OWNED_V1 '+json.dumps({'schema':1,'engine':engine,'architectures':ARCHES[engine], 'checks':checks,'executionIdentity':identity,'bundleSha256':digest,'ownedFixtures':'passed','engineReadiness':'not-tested','vmIsolation':'not-attested'},sort_keys=True,separators=(',',':')))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        # This developer-only test runs BEFORE boot credentials, and accepts only
        # checked-in owned fixtures. Bounded diagnostic text never contains a target.
        print('CLINE_MANAGED_ENGINE_FAILED_V1 '+type(error).__name__+': '+str(error)[:400],file=sys.stderr)
        raise SystemExit(1)
