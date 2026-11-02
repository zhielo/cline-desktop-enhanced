"""Public inert cold-boot check; never an engine/ownership/containment receipt."""
import hashlib
import json
import socket
import sys
import time

sys.path.insert(0, "/opt/cline")
from probe_protocol import FIXTURE_SHA256, encode_frame, receive_frame


def main():
    if sys.platform != "linux" or not hasattr(socket, "AF_VSOCK"):
        raise RuntimeError("Guest VSOCK core unavailable")
    # Actual guest-kernel family creation, NOT a Hyper-V host connection.
    with socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM, 0):
        pass
    key, session = bytes(range(32)), bytes(range(16))  # Public owned fixture only.
    request = {"operation": "owned-probe", "challenge": "ab" * 32}
    frame = encode_frame(key, session, 1, request)
    left, right = socket.socketpair()
    with left, right:
        left.sendall(frame)
        value = receive_frame(right, key, session, 1, time.monotonic() + 1)
    if value != request:
        raise RuntimeError("Guest inert protocol mismatch")
    expected = hashlib.sha256(b"cline-managed-owned-inert-fixture/v1\n").hexdigest()
    if FIXTURE_SHA256 != expected:
        raise RuntimeError("Guest inert fixture mismatch")
    print("CLINE_MANAGED_INERT_BOOT_V1 " + json.dumps({
        "fixtureSha256": expected, "vmIsolation": "not-attested",
        "engineReadiness": "not-tested", "hypervExchange": "not-tested",
    }, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
