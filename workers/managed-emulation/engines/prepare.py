"""CI-only runtime construction. Fixed repository-owned adapters; no target input.

Build tools and package-manager scripts run in the disposable build container,
not the developer host or final guest. No emulator/fixture runs during build.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import python_inputs
import native_rebuild

ROOT = Path('/opt/cline-engine')
ENGINES = ('qiling', 'unidbg', 'rnidbg', 'speakeasy')


def run(*command, env=None):
    subprocess.run(command, check=True, timeout=900, env=env)


def manifest(root, engine):
    if engine not in ENGINES:
        raise ValueError('Unknown fixed engine')
    files = {}
    size = 0
    for path in sorted(root.rglob('*')):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            target = os.readlink(path)
            if '\x00' in target or len(target) > 1024:
                raise ValueError('Runtime link budget')
            files[relative] = {'kind': 'symlink', 'target': target}
        elif path.is_file():
            length = path.stat().st_size
            size += length
            if length > 64 * 1024**2 or size > 384 * 1024**2:
                raise ValueError('Engine runtime byte budget')
            files[relative] = {'kind': 'file', 'size': length, 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
        elif not path.is_dir():
            raise ValueError('Special runtime file')
        if len(files) > 20_000:
            raise ValueError('Engine runtime count budget')
    return {'schema': 1, 'engine': engine, 'scope': 'development-owned-guest-tests-only', 'files': files}


def prepare(engine):
    if engine not in ENGINES or ROOT.exists():
        raise ValueError('New fixed engine runtime required')
    components, profiles = python_inputs.load(Path('/build'))
    ROOT.mkdir(mode=0o755)
    (ROOT/'engine').write_text(engine+'\n')
    shutil.copyfile('/build/managed/selftest.py', ROOT/'selftest.py')
    # Each final guest has ONE engine. Incompatible Unicorn versions never share
    # a Python environment, and the desktop's existing Unicorn is not modified.
    run('/usr/local/bin/python3.13', '-m', 'venv', str(ROOT/'env'))
    python = str(ROOT/'env/bin/python')
    if engine in ('qiling', 'speakeasy'):
        # Pin actual distribution bytes, not merely version names. Fetch is
        # data-only; pip gets a local hash-checked repository, no package index
        # and no network-resolved PEP 517 build dependencies.
        archives = Path('/build/private-python-archives')
        tools = Path('/build/private-python-tools')
        if tools.exists() or tools.is_symlink():
            raise ValueError('New private Python build-tool directory required')
        python_inputs.fetch(components, profiles, engine, archives)
        run(python, '-m', 'pip', '--isolated', 'install', '--no-cache-dir', '--no-index',
            '--find-links', str(archives), '--require-hashes', '--target', str(tools),
            '-r', '/build/managed/requirements-build.lock')
        run(python, '-m', 'pip', '--isolated', 'install', '--no-cache-dir', '--no-index',
            '--find-links', str(archives), '--require-hashes', '--no-build-isolation',
            '--ignore-installed', '-r', '/build/managed/requirements-'+engine+'.lock',
            env={**os.environ, 'PYTHONPATH':str(tools)})
    if engine in ('qiling', 'unidbg', 'rnidbg'):
        run('bash', '/build/emulation/build-fixtures.sh')
        shutil.copytree('/build/emulation/fixtures/build', ROOT/'fixtures')
    if engine == 'qiling':
        shutil.copyfile('/build/emulation/qiling_runner.py', ROOT/'qiling_runner.py')
    elif engine == 'unidbg':
        run('mvn', '-B', '-q', '-f', '/build/emulation/unidbg/pom.xml', 'package', 'dependency:copy-dependencies', '-DskipTests')
        build = Path('/build/emulation/unidbg/target')
        expected = {}
        for line in Path('/build/emulation/unidbg/dependencies.sha256').read_text().splitlines():
            digest, label = line.split(maxsplit=1)
            expected[Path(label.lstrip('*')).name] = digest
        jars = {p.name: p for p in (build/'dependency').glob('*.jar')}
        if set(jars) != set(expected) or any(hashlib.sha256(p.read_bytes()).hexdigest() != expected[n] for n,p in jars.items()):
            raise ValueError('Exact JNI dependency closure required')
        # Fake-backend unit test only: no emulator, native backend or fixture is
        # instantiated during build. Real execution remains in the guest gate.
        run('/usr/lib/jvm/java-17-openjdk-amd64/bin/java', '-cp', str(build/'classes')+':'+str(build/'test-classes')+':'+str(build/'dependency/*'), 'ClineGuardTest')
        # Compile only. This standalone JDK diagnostic has no emulator/JAR
        # dependency and is never run in the builder or on a successful boot.
        run('/usr/lib/jvm/java-17-openjdk-amd64/bin/javac', '--release', '17',
            '-d', str(ROOT/'jvm-probe'), '/build/managed/OwnedJvmProbe.java')
        shutil.copytree(build/'classes', ROOT/'classes')
        shutil.copytree(build/'dependency', ROOT/'dependency')
        native_rebuild.build(ROOT, Path('/build/private-unidbg-native'))
        run('/usr/lib/jvm/java-17-openjdk-amd64/bin/jlink', '--add-modules', 'java.base,java.logging,java.desktop,java.management,java.naming,jdk.unsupported', '--compress=2', '--strip-debug', '--no-header-files', '--no-man-pages', '--output', str(ROOT/'jre'))
    elif engine == 'rnidbg':
        run('bash', '/build/emulation/build-rnidbg.sh')
        shutil.copyfile('/build/emulation/rnidbg/target/release/cline-rnidbg-runner', ROOT/'jni-runner')
        run('strip', '--strip-unneeded', str(ROOT/'jni-runner'))
        (ROOT/'jni-runner').chmod(0o755)
    else:
        shutil.copyfile('/build/re-analysis/collector.py', ROOT/'collector.py')
        shutil.copyfile('/build/re-analysis/collector.test.py', ROOT/'owned_pe.py')
    # Fixed reviewed shared-library family; do not copy build tools/package caches.
    libs = ROOT/'syslibs'
    libs.mkdir()
    for name in ('libstdc++.so.6','libgcc_s.so.1','libz.so.1','libzstd.so.1','libssl.so.3','libcrypto.so.3','libatomic.so.1','libjpeg.so.62','libpng16.so.16','libfreetype.so.6','libbrotlidec.so.1','libbrotlicommon.so.1','libbz2.so.1.0','liblzma.so.5','libffi.so.8'):
        path = Path('/usr/lib/x86_64-linux-gnu')/name
        if path.is_file():
            shutil.copyfile(path, libs/name)
    # Remove caches, generated bytecode and package management from final runtime.
    for path in list(ROOT.rglob('__pycache__')):
        shutil.rmtree(path)
    for path in list(ROOT.rglob('*.pyc')):
        path.unlink()
    for path in (ROOT/'env/lib/python3.13/site-packages').glob('pip*'):
        shutil.rmtree(path) if path.is_dir() else path.unlink()
    for path in (ROOT/'env/bin').iterdir():
        if path.name not in ('python','python3','python3.13'):
            path.unlink()
    value = manifest(ROOT, engine)
    (ROOT/'bundle.json').write_text(json.dumps(value, sort_keys=True, separators=(',', ':')))
    print('Built bounded owned-guest runtime:', engine, len(value['files']))


if __name__ == '__main__':
    if len(sys.argv) != 2:
        raise SystemExit('One fixed engine required')
    prepare(sys.argv[1])
