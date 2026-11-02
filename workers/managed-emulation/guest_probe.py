"""One-shot AF_VSOCK inert probe; development foundation, not a managed installer.

No TCP/HTTP fallback and no automatic service registration. Missing provisioning
or AF_VSOCK support is a hard failure. The future image/lifecycle broker owns the
private boot credential and must rotate it for every disposable guest.
"""
import os
from contextlib import ExitStack
import socket
import stat
import sys
import time

from probe_protocol import ProbeRejected, exact_hex, parse_json, serve_one

PORT = 35555


def _open_private_boot_record():
    # Pin every parent by descriptor. O_NOFOLLOW on the leaf alone does not
    # prevent a linked/writable parent from redirecting the boot credential.
    if not all(hasattr(os, name) for name in ("O_DIRECTORY", "O_NOFOLLOW", "O_NONBLOCK")):
        raise ProbeRejected("Safe credential path primitives required")
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK
    with ExitStack() as owned:
        descriptor = None
        for component, private in (("/", False), ("run", False), ("cline-managed-probe", True)):
            current = os.open(component, directory_flags, dir_fd=descriptor)
            owned.callback(os.close, current)
            info = os.fstat(current)
            mode = stat.S_IMODE(info.st_mode)
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
                    or mode & 0o022 or (private and mode != 0o700)):
                raise ProbeRejected("Protected root-owned boot directory required")
            descriptor = current
        return os.open("boot.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=descriptor)


def read_boot_config(now=None):
    # No caller-provided path, environment override, symlink traversal or fallback.
    descriptor = _open_private_boot_record()
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1 or not 1 <= info.st_size <= 1024:
            raise ProbeRejected("Private root-owned boot record required")
        data = os.read(descriptor, 1025)
        after = os.fstat(descriptor)
        identity_fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
        if len(data) != info.st_size or any(getattr(info, field) != getattr(after, field) for field in identity_fields):
            raise ProbeRejected("Boot record changed")
    finally:
        os.close(descriptor)
    value = parse_json(data)
    if not isinstance(value, dict) or set(value) != {"protocol", "session", "key", "expiresAt"} or value["protocol"] != "cline-managed-inert-probe/v1":
        raise ProbeRejected("Exact boot record required")
    session = exact_hex(value["session"], 16)
    key = exact_hex(value["key"], 32)
    current = time.time() if now is None else now
    expiry = value["expiresAt"]
    if type(expiry) is not int or not current < expiry <= current + 300:
        raise ProbeRejected("Fresh bounded boot record required")
    return key, session, expiry


def main():
    if sys.platform != "linux" or not hasattr(socket, "AF_VSOCK"):
        raise ProbeRejected("Linux Hyper-V VSOCK guest required")
    key, session, expiry = read_boot_config()
    deadline = time.monotonic() + min(30, expiry - time.time())
    with socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM, 0) as server:
        server.settimeout(max(0.001, deadline - time.monotonic()))
        server.bind((socket.VMADDR_CID_ANY, PORT))
        server.listen(1)
        connection, peer = server.accept()
        with connection:
            # Host CID only. Peer location complements, never replaces, the MAC.
            if peer[0] != socket.VMADDR_CID_HOST:
                raise ProbeRejected("Host peer required")
            serve_one(connection, key, session, deadline)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        # Never echo credentials, request bytes, environment or raw OS errors.
        print("Managed inert probe failed; no readiness established.", file=sys.stderr)
        raise SystemExit(1)