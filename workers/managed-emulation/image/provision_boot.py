"""Copy one bounded credential from fixed read-only media into private tmpfs.

No media writer/broker is implemented here. Never prints credential bytes/errors.
"""
import os
import stat
import sys

sys.path.insert(0, "/opt/cline")
from guest_probe import read_boot_config

SOURCE = "/mnt/cline-boot/BOOT.JSON"
DESTINATION = "/run/cline-managed-probe/boot.json"


def main():
    # The fixed mountpoint is created by root PID 1 in the reviewed image.
    descriptor = os.open(SOURCE, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or not 1 <= before.st_size <= 1024:
            raise ValueError("Credential media record rejected")
        data = os.read(descriptor, 1025)
        after = os.fstat(descriptor)
        fields = ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns")
        if len(data) != before.st_size or any(getattr(before, k) != getattr(after, k) for k in fields):
            raise ValueError("Credential media changed")
    finally:
        os.close(descriptor)
    target = os.open(DESTINATION, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        view = memoryview(data)
        while view:
            count = os.write(target, view)
            if count <= 0:
                raise ValueError("Credential write rejected")
            view = view[count:]
    finally:
        os.close(target)
    # Invalid content never starts the listener. PID 1 powers off on any failure.
    read_boot_config()


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("Managed guest provisioning rejected.", file=sys.stderr)
        raise SystemExit(1)
