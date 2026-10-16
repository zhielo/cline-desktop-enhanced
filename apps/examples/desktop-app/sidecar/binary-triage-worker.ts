/** Fixed host-owned worker. No target imports, arbitrary Python or r2 command input. */
export const BINARY_TRIAGE_WORKER = String.raw`
import sys, json, os, hashlib, subprocess, importlib.metadata

phase = "request"

def main(req):
    global phase
    op = req['operation']
    target = req['target']
    if os.path.getsize(target) > 64 * 1024 * 1024:
        raise ValueError('Input budget exceeded')
    with open(target, 'rb') as f:
        head = f.read(4)
    fmt = 'pe' if head[:2] == b'MZ' else 'elf' if head == b'\x7fELF' else 'other'
    if op == 'scan_yara':
        phase = "yara-import"
        import yara
        phase = "yara-rules"
        rules = yara.compile(filepath=req['rules'], includes=False, error_on_warning=True)
        matches = rules.match(target, timeout=20)
        return {'engine': 'yara', 'version': yara.__version__, 'format': fmt,
                'category': 'rule-match', 'data': [{'rule': m.rule, 'namespace': m.namespace, 'tags': m.tags} for m in matches[:200]],
                'coverage': 'Reviewed bundled triage rules only; no match does not mean safe.'}
    if fmt not in ('pe', 'elf'):
        raise ValueError('Unsupported target: native analysis accepts PE/ELF only')
    if op in ('inspect_binary', 'list_functions', 'get_function_disassembly', 'find_references'):
        phase = "r2-import"
        import r2pipe
        phase = "r2-open"
        r = r2pipe.open(target, flags=['-2', '-N', '-S', '-e', 'scr.color=0', '-e', 'cfg.plugins=false'], radare2home=os.path.dirname(req['executable']))
        try:
            phase = "r2-inspect"
            version = str((r.cmdj('?Vj') or {}).get('version', 'unknown'))
            info = r.cmdj('ij')
            if not isinstance(info, dict) or not info.get('bin', {}).get('arch'):
                raise ValueError('Native structure unavailable')
            if op == 'inspect_binary':
                data = {'info': info, 'imports': r.cmdj('iij'), 'exports': r.cmdj('iEj')}
            else:
                r.cmd('aa')
                if op == 'list_functions':
                    data = (r.cmdj('aflj') or [])[:500]
                else:
                    address = req.get('address')
                    if not isinstance(address, int) or isinstance(address, bool) or address < 0 or address > 0xffffffffffffffff:
                        raise ValueError('Exact numeric address required')
                    command = ('pdj 128 @ ' if op == 'get_function_disassembly' else 'axtj @ ') + hex(address)
                    data = (r.cmdj(command) or [])[:500]
            return {'engine': 'radare2', 'version': version, 'bindingVersion': importlib.metadata.version('r2pipe'),
                    'format': fmt, 'category': 'derived', 'data': data,
                    'coverage': 'Bounded static analysis; references/functions are candidates. Disassembly is at most 128 instructions, not a complete function or execution proof.'}
        finally:
            r.quit()
    if op == 'identify_capabilities':
        argv = [req['executable'], '-j', target]
        engine = 'capa'
    elif op == 'extract_strings':
        if fmt != 'pe':
            raise ValueError('This adapter supports FLOSS static extraction for PE only')
        argv = [req['executable'], '-j', '--only', 'static', '--', target]
        engine = 'floss'
    else:
        raise ValueError('Unsupported fixed operation')
    # Parent supervisor bounds lifetime/output and terminates the entire process tree.
    phase = "native-launch"
    process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=sys.stderr)
    output = bytearray()
    try:
        while True:
            chunk = process.stdout.read(65536)
            if not chunk:
                break
            if len(output) + len(chunk) > 768 * 1024:
                raise ValueError('Engine result exceeds output budget')
            output.extend(chunk)
        if process.wait() != 0:
            raise ValueError('Engine failed')
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
    phase = "native-result"
    data = json.loads(output)
    metadata = data.get('metadata' if engine == 'floss' else 'meta', {})
    if not metadata.get('version'):
        raise ValueError('Engine provenance unavailable')
    if engine == 'capa' and (metadata.get('flavor') != 'static' or not metadata.get('analysis', {}).get('arch')):
        raise ValueError('Static capability coverage unavailable')
    return {'engine': engine, 'version': str(data.get('metadata' if engine == 'floss' else 'meta', {}).get('version', 'unknown')), 'format': fmt, 'category': 'derived', 'data': data,
            'coverage': 'Static supported-format evidence only; packed/obfuscated inputs may be incomplete. No target execution or FLOSS decoding is enabled.'}

try:
    raw = sys.stdin.buffer.read(16385)
    if len(raw) > 16384:
        raise ValueError('Request budget exceeded')
    result = main(json.loads(raw))
    encoded = json.dumps(result, ensure_ascii=True)
    if len(encoded) > 2 * 1024 * 1024:
        raise ValueError('Result budget exceeded')
    print(encoded)
except Exception as exc:
    # Never print raw subprocess arguments, target content, credentials or exception text.
    print(json.dumps({'error': 'Analysis failed', 'errorType': type(exc).__name__, 'phase': phase}))
    sys.exit(1)
`;
