"""Exact private Python build inputs; CI-only, not a desktop engine installer.

Fetch fixed committed artifact URLs as bounded data and verify SHA-256 before
pip sees them. Source archive references are an inventory, NOT a complete
corresponding-source bundle/license review or permission to publish a runtime.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import time
import urllib.parse
import urllib.request

HERE = Path(__file__).resolve().parent
PROFILE = 'cpython-3.13-linux-x86_64-glibc-2.36'
BUILD = ['setuptools==80.9.0', 'wheel==0.45.1']
MAX_FILE = 256 * 1024**2
MAX_SELECTED = 384 * 1024**2
HEADERS = {
    'build': '# Private build-only tools, never installed into the shipping engine environment.\n',
    'runtime': '# Exact private owned-guest artifacts; no desktop/HTTPS worker dependency change.\n',
}


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate private Python input field')
        result[key] = value
    return result


def keys(value, expected):
    if not isinstance(value, dict) or set(value) != set(expected):
        raise ValueError('Private Python input schema')


def label(line):
    if not isinstance(line, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*==[A-Za-z0-9][A-Za-z0-9_.+!-]*', line):
        raise ValueError('Exact private Python requirement required')
    name, version = line.split('==')
    return re.sub('[-_.]+', '-', name).lower() + '==' + version


def requirements(path):
    lines = [label(line) for line in path.read_text().splitlines() if line and not line.startswith('#')]
    if not lines or len(lines) != len(set(lines)) or len({line.split('==')[0] for line in lines}) != len(lines):
        raise ValueError('Distinct private Python requirements required')
    return sorted(lines)


def artifact(value, source=False):
    keys(value, ['filename', 'url', 'bytes', 'sha256'])
    filename = value['filename']
    if not isinstance(filename, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.+-]{0,199}', filename) or '..' in filename:
        raise ValueError('Private Python artifact filename')
    if not filename.endswith(('.tar.gz', '.zip') if source else ('.tar.gz', '.zip', '.whl')):
        raise ValueError('Private Python artifact type')
    if type(value['bytes']) is not int or not 0 < value['bytes'] <= MAX_FILE or not isinstance(value['sha256'], str) or not re.fullmatch('[0-9a-f]{64}', value['sha256']):
        raise ValueError('Private Python artifact integrity/budget')
    url(value['url'], filename)


def url(value, filename):
    if not isinstance(value, str) or len(value) > 2048:
        raise ValueError('Private Python artifact URL')
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme != 'https' or parsed.netloc != 'files.pythonhosted.org' or parsed.query or parsed.fragment or not parsed.path.startswith('/packages/') or not parsed.path.endswith('/' + filename) or any(ord(c) < 33 for c in value) or '%' in parsed.path or '\\' in value or any(p in ('.', '..') for p in parsed.path.split('/')):
        raise ValueError('Private Python artifact origin/path')


def render(profile, selected, components):
    return HEADERS['build' if profile == 'build' else 'runtime'] + ''.join(
        item + ' --hash=sha256:' + components[item]['install']['sha256'] + '\n' for item in selected)


def load(requirements_root=None, lock_root=HERE):
    requirements_root = requirements_root or HERE.parents[1]
    raw = (lock_root/'python-inputs.lock.json').read_bytes()
    if not 1 <= len(raw) <= 256 * 1024:
        raise ValueError('Private Python inventory budget')
    value = json.loads(raw, object_pairs_hook=unique)
    keys(value, ['schemaVersion', 'scope', 'profile', 'components'])
    if type(value['schemaVersion']) is not int or value['schemaVersion'] != 1 or value['scope'] != 'development-owned-guest-python-inputs-only' or value['profile'] != PROFILE:
        raise ValueError('Private Python input scope/profile')
    profiles = {
        'qiling': requirements(requirements_root/'emulation/requirements-qiling.txt'),
        'speakeasy': requirements(requirements_root/'re-analysis/requirements.txt'),
        'build': BUILD,
    }
    components = value['components']
    expected = set().union(*profiles.values())
    keys(components, expected)
    for item, entry in components.items():
        if label(item) != item:
            raise ValueError('Canonical private Python component required')
        keys(entry, ['source', 'install'])
        artifact(entry['source'], source=True)
        artifact(entry['install'])
        if not entry['install']['filename'].endswith('.whl') and entry['install'] != entry['source']:
            raise ValueError('Private Python source build must use pinned source')
    for profile, selected in profiles.items():
        if (lock_root/f'requirements-{profile}.lock').read_text() != render(profile, selected, components):
            raise ValueError('Private Python requirement lock differs from pinned inventory')
        if sum(components[item]['install']['bytes'] for item in set(selected + BUILD)) > MAX_SELECTED:
            raise ValueError('Private Python selected input budget')
    return components, profiles


def selected_artifacts(components, profiles, engine):
    if engine not in ('qiling', 'speakeasy'):
        raise ValueError('Fixed Python engine required')
    return [components[item]['install'] for item in sorted(set(profiles[engine] + BUILD))]


def fetch(components, profiles, engine, output, opener=urllib.request.urlopen):
    # Fixed CI build directory only; never accepts a desktop IPC path or manifest.
    artifacts = selected_artifacts(components, profiles, engine)
    names = [entry['filename'] for entry in artifacts]
    if len(names) != len(set(names)):
        raise ValueError('Duplicate private Python artifact filename')
    overall_deadline = time.monotonic() + 600
    output.mkdir(mode=0o700)  # exclusive: no resume/adoption of partially fetched inputs
    for entry in artifacts:
        deadline = min(overall_deadline, time.monotonic() + 120)
        if time.monotonic() >= deadline:
            raise ValueError('Private Python artifact acquisition deadline')
        filename = entry['filename']
        request = urllib.request.Request(entry['url'], headers={'User-Agent': 'cline-managed-private-inputs/v1'})
        path = output/filename
        partial = output/(filename + '.part')
        with opener(request, timeout=30) as response, partial.open('xb') as stream:
            url(response.geturl(), filename)
            if response.status != 200:
                raise ValueError('Private Python artifact HTTP status')
            total, digest = 0, hashlib.sha256()
            while True:
                if time.monotonic() >= deadline:
                    raise ValueError('Private Python artifact acquisition deadline')
                block = response.read(65536)
                if time.monotonic() >= deadline:
                    raise ValueError('Private Python artifact acquisition deadline')
                if not block:
                    break
                total += len(block)
                if total > entry['bytes']:
                    raise ValueError('Private Python artifact byte budget')
                digest.update(block)
                if stream.write(block) != len(block):
                    raise ValueError('Private Python artifact short write')
            if total != entry['bytes'] or digest.hexdigest() != entry['sha256']:
                raise ValueError('Private Python artifact hash/length mismatch')
            stream.flush()
            os.fsync(stream.fileno())
        partial.rename(path)
    return len(artifacts)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('operation', choices=['verify', 'fetch'])
    parser.add_argument('--engine', choices=['qiling', 'speakeasy'])
    parser.add_argument('--output', type=Path)
    parser.add_argument('--requirements-root', type=Path)
    args = parser.parse_args()
    components, profiles = load(args.requirements_root)
    if args.operation == 'fetch':
        if args.engine is None or args.output is None:
            parser.error('Fixed engine and new build output required')
        count = fetch(components, profiles, args.engine, args.output)
        print('Verified private Python build artifacts:', args.engine, count)
    elif args.engine is not None or args.output is not None:
        parser.error('Verification accepts no engine/output')
    else:
        print('Private Python artifact inventory and exact version/hash locks verified')


if __name__ == '__main__':
    main()
