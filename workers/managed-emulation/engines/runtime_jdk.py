"""Build-container-only pinned JDK input. Never executes/downloads on app startup."""
import hashlib
import json
from pathlib import Path, PurePosixPath
import posixpath
import re
import tarfile
import urllib.request


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate private JDK field')
        result[key] = value
    return result


def load(path):
    value = json.loads(path.read_bytes(), object_pairs_hook=unique)
    if not isinstance(value, dict) or set(value) != {'schema','scope','version','root','url','bytes','sha256'} or type(value['schema']) is not int or value['schema'] != 1 or value['scope'] != 'development-owned-guest-tests-only':
        raise ValueError('Private JDK input schema')
    version = value['version']
    if not isinstance(version, str) or not re.fullmatch(r'21\.0\.[0-9]{1,3}\+[0-9]{1,3}', version) or value['root'] != 'jdk-'+version:
        raise ValueError('Private JDK release version')
    release, build = version.split('+')
    expected = 'https://github.com/adoptium/temurin21-binaries/releases/download/jdk-'+release+'%2B'+build+'/OpenJDK21U-jdk_x64_linux_hotspot_'+release+'_'+build+'.tar.gz'
    if value['url'] != expected or type(value['bytes']) is not int or not 0 < value['bytes'] <= 256*1024**2 or not isinstance(value['sha256'], str) or not re.fullmatch('[0-9a-f]{64}',value['sha256']):
        raise ValueError('Private JDK artifact identity')
    return value


def fetch(value, archive):
    digest = hashlib.sha256()
    size = 0
    with urllib.request.urlopen(value['url'], timeout=60) as response, archive.open('xb') as out:
        if response.status != 200:
            raise ValueError('Private JDK HTTP status')
        while block := response.read(min(1024*1024, value['bytes']-size+1)):
            size += len(block)
            if size > value['bytes']:
                raise ValueError('Private JDK download overflow')
            digest.update(block)
            out.write(block)
    if size != value['bytes'] or digest.hexdigest() != value['sha256']:
        raise ValueError('Private JDK download identity')


def extract(archive, destination, root):
    destination.mkdir(mode=0o700)
    with tarfile.open(archive, 'r:gz') as source:
        members = {}
        total = 0
        for member in source:
            name = member.name.rstrip('/')
            parts = name.split('/')
            if not name or name.startswith('/') or '\\' in name or '\x00' in name or any(p in ('','.','..') for p in parts) or parts[0] != root or name in members or len(members) >= 4096:
                raise ValueError('Private JDK archive path/count')
            if not (member.isdir() or member.isfile() or member.issym()) or member.size < 0 or member.size > 256*1024**2:
                raise ValueError('Private JDK archive type/size')
            total += member.size
            if total > 512*1024**2:
                raise ValueError('Private JDK expanded budget')
            members[name] = member
        # Extract regular members in archive order, then materialize legal aliases
        # from those bytes. This avoids repeatedly seeking/reinflating the gzip
        # stream for hundreds of forward/backward legal-notice references.
        aliases = []
        for name, member in members.items():
            parts = PurePosixPath(name).parts[1:]
            if not parts:
                if not member.isdir():
                    raise ValueError('Private JDK root directory required')
                continue
            target = destination.joinpath(*parts)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            if member.issym():
                label = posixpath.normpath(posixpath.join(posixpath.dirname(name), member.linkname))
                if not name.startswith(root+'/legal/') or not label.startswith(root+'/legal/') or '\\' in member.linkname or '\x00' in member.linkname or member.linkname.startswith('/') or label not in members or not members[label].isfile():
                    raise ValueError('Private JDK legal link refused')
                total += members[label].size
                if total > 512*1024**2:
                    raise ValueError('Private JDK expanded alias budget')
                aliases.append((target, destination.joinpath(*PurePosixPath(label).parts[1:]), members[label]))
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with source.extractfile(member) as stream, target.open('xb') as out:
                copy_exact(stream, out, member.size)
            target.chmod(0o755 if member.mode & 0o111 else 0o644)
        # No filesystem links are created; only direct regular legal members.
        for target, original, member in aliases:
            if original.is_symlink() or not original.is_file() or original.stat().st_size != member.size:
                raise ValueError('Private JDK legal alias source')
            target.parent.mkdir(parents=True, exist_ok=True)
            with original.open('rb') as stream, target.open('xb') as out:
                copy_exact(stream, out, member.size)
            target.chmod(0o755 if member.mode & 0o111 else 0o644)


def copy_exact(stream, out, size):
    remaining = size
    while remaining:
        block = stream.read(min(1024*1024, remaining))
        if not block:
            raise ValueError('Private JDK archive short read')
        out.write(block)
        remaining -= len(block)
    if stream.read(1):
        raise ValueError('Private JDK archive length')


def verify_release(home, version):
    path = home/'release'
    if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= 16384:
        raise ValueError('Private JDK release file')
    expected = {'IMPLEMENTOR':'"Eclipse Adoptium"', 'JAVA_RUNTIME_VERSION':'"'+version+'-LTS"', 'OS_ARCH':'"x86_64"', 'OS_NAME':'"Linux"', 'LIBC':'"gnu"'}
    observed = {}
    for line in path.read_text().splitlines():
        key, separator, value = line.partition('=')
        if key in expected:
            if not separator or key in observed:
                raise ValueError('Private JDK release fields')
            observed[key] = value
    if observed != expected:
        raise ValueError('Private JDK release mismatch')


REQUIRED_MODULES = frozenset(('java.base', 'java.logging', 'java.desktop',
                             'java.management', 'java.naming', 'jdk.unsupported'))


def verify_linked_release(home, version):
    # jlink emits JAVA_VERSION/MODULES, not the full input JDK release identity.
    # Vendor/platform identity is checked on the authenticated input beforehand.
    path = home/'release'
    if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= 16384:
        raise ValueError('Private linked JRE release file')
    observed = {}
    for line in path.read_text().splitlines():
        key, separator, value = line.partition('=')
        if key in ('JAVA_VERSION', 'MODULES'):
            if not separator or key in observed:
                raise ValueError('Private linked JRE release fields')
            observed[key] = value
    modules = observed.get('MODULES', '')
    if observed.get('JAVA_VERSION') != '"'+version.split('+')[0]+'"' or not re.fullmatch(r'"[a-z0-9.]+(?: [a-z0-9.]+)*"', modules):
        raise ValueError('Private linked JRE release mismatch')
    values = modules[1:-1].split(' ')
    # Dependencies may add platform modules; build tooling is never admitted.
    if len(set(values)) != len(values) or not REQUIRED_MODULES.issubset(values) or set(values).intersection(('jdk.compiler', 'jdk.jlink', 'jdk.jartool')):
        raise ValueError('Private linked JRE module closure')


def obtain(directory):
    value = load(Path(__file__).with_name('runtime-jdk.lock.json'))
    directory.mkdir(mode=0o700)
    archive = directory/'pinned.tar.gz'
    fetch(value, archive)
    home = directory/'jdk'
    extract(archive, home, value['root'])
    verify_release(home, value['version'])
    return home, value
