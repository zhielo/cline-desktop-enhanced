"""Fixed owned-engine guest entry; not an installer or arbitrary-target service.

Drop root and all supplementary groups before importing any emulator/native
backend. No parameters, shell, user executable, worker endpoint or fallback.
"""
import ctypes
import os
import resource
import sys

ENGINE_UID = 65534
PR_SET_NO_NEW_PRIVS = 38
PR_GET_NO_NEW_PRIVS = 39
PYTHON = '/opt/cline-engine/env/bin/python'
SELFTEST = '/opt/cline-engine/selftest.py'
PRIVATE_DIRECTORY = '/run/cline-engine-private-test'
PRIVATE_MARKER = PRIVATE_DIRECTORY+'/owned-marker'
IDENTITY = 'uid-gid-65534/no-supplementary-groups/no-new-privileges'


def no_new_privileges():
    libc = ctypes.CDLL(None, use_errno=True)
    prctl = libc.prctl
    prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
    prctl.restype = ctypes.c_int
    if prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 or prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1:
        raise ValueError('Guest no-new-privileges unavailable')


def provision_private_marker():
    # Public owned fixture, NOT a boot key. The fresh private parent demonstrates
    # actual guest permission denial, rather than treating a missing file as proof.
    os.mkdir(PRIVATE_DIRECTORY, 0o700)
    descriptor = os.open(PRIVATE_MARKER, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        marker = b'owned private access-denial fixture\n'
        if os.write(descriptor, marker) != len(marker):
            raise ValueError('Owned private fixture write failed')
    finally:
        os.close(descriptor)


def private_marker_unreadable():
    try:
        descriptor = os.open(PRIVATE_MARKER, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except PermissionError:
        return
    else:
        os.close(descriptor)
        raise ValueError('Unprivileged engine can read root-private fixture')


def no_capabilities():
    with open('/proc/self/status', 'rb') as stream:
        raw = stream.read(16385)
    if len(raw) > 16384:
        raise ValueError('Guest process status budget')
    required = {b'CapInh',b'CapPrm',b'CapEff',b'CapAmb'}
    seen = set()
    for line in raw.splitlines():
        key,separator,value = line.partition(b':')
        if key in required:
            value = value.strip()
            if key in seen or not separator or value != b'0'*16:
                raise ValueError('Guest engine capabilities must be empty')
            seen.add(key)
    if seen != required:
        raise ValueError('Guest engine capability observation incomplete')


def verify_identity():
    if sys.platform != 'linux' or os.getresuid() != (ENGINE_UID,)*3 or os.getresgid() != (ENGINE_UID,)*3 or os.getgroups():
        raise ValueError('Unprivileged guest engine identity required')
    libc = ctypes.CDLL(None, use_errno=True)
    prctl = libc.prctl
    prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
    prctl.restype = ctypes.c_int
    if prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1:
        raise ValueError('Guest no-new-privileges required')
    no_capabilities()
    private_marker_unreadable()
    return IDENTITY


def main():
    if len(sys.argv) != 1 or sys.platform != 'linux' or os.getresuid() != (0,0,0) or os.getresgid() != (0,0,0):
        raise ValueError('Fixed root-owned guest entry required')
    no_new_privileges()
    resource.setrlimit(resource.RLIMIT_CORE, (0,0))
    provision_private_marker()
    os.setgroups([])
    os.setresgid(ENGINE_UID, ENGINE_UID, ENGINE_UID)
    os.setresuid(ENGINE_UID, ENGINE_UID, ENGINE_UID)
    verify_identity()
    # -I excludes cwd/user/site/environment injection. Only fixed image paths
    # and a private dependency closure are used; no inherited worker secrets.
    os.chdir('/')
    os.execve(PYTHON, [PYTHON, '-B', '-I', SELFTEST], {
        'PATH':'/usr/bin:/usr/local/bin', 'HOME':'/tmp', 'LANG':'C.UTF-8',
        'LD_LIBRARY_PATH':'/opt/cline-engine/syslibs:/usr/local/lib',
        'PYTHONDONTWRITEBYTECODE':'1',
    })
    raise ValueError('Guest engine exec unexpectedly returned')


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('CLINE_MANAGED_ENGINE_ENTRY_REJECTED_V1', file=sys.stderr)
        raise SystemExit(1)
