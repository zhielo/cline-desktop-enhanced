"""Owned protocol fixtures. Socketpair results are NOT Hyper-V/VM evidence."""
import io
import json
import os
from pathlib import Path
import socket
import stat
import struct
import threading
import time
import types
import unittest
from unittest import mock

import guest_probe
from probe_protocol import (
    DOMAIN, FIXTURE_SHA256, MAX_FRAME, PROTOCOL, ProbeRejected,
    encode_frame, exact_hex, parse_json, receive_frame, serve_one,
)

KEY = bytes(range(32))
SESSION = bytes(range(16))
CHALLENGE = "ab" * 32
REQUEST = {"operation": "owned-probe", "challenge": CHALLENGE}


class BufferedSocket:
    def __init__(self, data):
        self.data = io.BytesIO(data)
        self.reads = []

    def settimeout(self, value):
        if value <= 0:
            raise TimeoutError()

    def recv(self, size):
        self.reads.append(size)
        return self.data.read(size)


def receive(data, key=KEY, session=SESSION, sequence=1):
    return receive_frame(BufferedSocket(data), key, session, sequence, time.monotonic() + 1)


def mutate(frame, **fields):
    value = json.loads(frame[4:])
    value.update(fields)
    body = json.dumps(value, separators=(",", ":")).encode()
    return struct.pack(">I", len(body)) + body


class ProtocolTests(unittest.TestCase):
    def test_authenticated_request_and_direction(self):
        frame = encode_frame(KEY, SESSION, 1, REQUEST)
        self.assertEqual(receive(frame), REQUEST)
        for kwargs in [
            {"key": b"\xff" * 32},
            {"session": b"\xff" * 16},
            {"sequence": 2},
        ]:
            with self.subTest(kwargs=kwargs), self.assertRaises(ProbeRejected):
                receive(frame, **kwargs)

    def test_tampering_and_unauthenticated_envelopes_fail(self):
        frame = encode_frame(KEY, SESSION, 1, REQUEST)
        for fields in [
            {"mac": "0" * 64}, {"mac": "A" * 64},
            {"protocol": "other"}, {"sequence": True},
            {"sequence": 0}, {"payload": "a"}, {"payload": "GG"},
            {"payload": "00" * 1025}, {"extra": "forbidden"},
        ]:
            with self.subTest(fields=fields), self.assertRaises(ProbeRejected):
                receive(mutate(frame, **fields))

    def test_duplicate_fields_are_not_silently_overwritten(self):
        frame = encode_frame(KEY, SESSION, 1, REQUEST)
        body = frame[4:].replace(b'"sequence":1', b'"sequence":1,"sequence":1')
        with self.assertRaises(ProbeRejected):
            receive(struct.pack(">I", len(body)) + body)
        with self.assertRaises(ProbeRejected):
            parse_json(b'{"operation":"owned-probe","operation":"shell"}')

    def test_oversized_header_rejected_before_body_read(self):
        stream = BufferedSocket(struct.pack(">I", MAX_FRAME + 1))
        with self.assertRaises(ProbeRejected):
            receive_frame(stream, KEY, SESSION, 1, time.monotonic() + 1)
        self.assertEqual(stream.reads, [4])

    def test_truncated_invalid_empty_and_expired_frames_fail(self):
        for data in [b"", b"\0", struct.pack(">I", 0), struct.pack(">I", 20) + b"{}",
                     struct.pack(">I", 1) + b"\xff"]:
            with self.subTest(data=data), self.assertRaises(ProbeRejected):
                receive(data)
        stream = BufferedSocket(encode_frame(KEY, SESSION, 1, REQUEST))
        with self.assertRaises(ProbeRejected):
            receive_frame(stream, KEY, SESSION, 1, time.monotonic() - 1)
        self.assertEqual(stream.reads, [])

    def test_slow_reader_cannot_reset_absolute_deadline(self):
        class Slow(BufferedSocket):
            def recv(self, size):
                time.sleep(0.015)
                return super().recv(1)
        start = time.monotonic()
        with self.assertRaises(ProbeRejected):
            receive_frame(Slow(encode_frame(KEY, SESSION, 1, REQUEST)),
                          KEY, SESSION, 1, start + 0.035)
        self.assertLess(time.monotonic() - start, 1)

    def test_real_socketpair_serves_fixed_fixture_only(self):
        errors = []
        host, guest = socket.socketpair()
        def owned_server():
            with guest:
                try:
                    serve_one(guest, KEY, SESSION, time.monotonic() + 2)
                except Exception as error:
                    errors.append(error)
        thread = threading.Thread(target=owned_server, daemon=True)
        thread.start()
        try:
            host.sendall(encode_frame(KEY, SESSION, 1, REQUEST))
            result = receive_frame(host, KEY, SESSION, 2, time.monotonic() + 2)
            self.assertEqual(result, {
                "operation": "owned-probe-result", "challenge": CHALLENGE,
                "fixtureSha256": FIXTURE_SHA256, "execution": "owned-fixture-only",
                "vmIsolation": "not-attested", "engineReadiness": "not-tested",
            })
            thread.join(timeout=2)
            self.assertFalse(thread.is_alive())
            self.assertEqual(errors, [])
            self.assertEqual(host.recv(1), b"")  # one shot, not a persistent executor
        finally:
            host.close()
            thread.join(timeout=2)

    def test_shell_paths_targets_and_extra_options_are_rejected(self):
        for request in [
            {"operation": "shell", "challenge": CHALLENGE},
            {**REQUEST, "target": "/etc/passwd"},
            {**REQUEST, "command": "anything"},
            {**REQUEST, "challenge": "invalid"},
            [],
        ]:
            class Exchange(BufferedSocket):
                def sendall(self, _):
                    raise AssertionError("Invalid request must not receive a result")
            with self.subTest(request=request), self.assertRaises(ProbeRejected):
                serve_one(Exchange(encode_frame(KEY, SESSION, 1, request)),
                          KEY, SESSION, time.monotonic() + 1)

    def test_hex_input_is_canonical_and_exact(self):
        for value in ["", "aa", "AA" * 32, "ab" * 31, "ab" * 33, None, 1]:
            with self.subTest(value=value), self.assertRaises(ProbeRejected):
                exact_hex(value, 32)

    def test_cross_language_public_vectors(self):
        vector = json.loads((Path(__file__).parent / "protocol-vectors.json").read_text())
        self.assertEqual(DOMAIN.hex(), vector["domainHex"])
        self.assertEqual(encode_frame(KEY, SESSION, 1, REQUEST).hex(), vector["requestFrameHex"])
        response = receive(bytes.fromhex(vector["responseFrameHex"]), sequence=2)
        self.assertEqual(response["fixtureSha256"], FIXTURE_SHA256)
        self.assertEqual(response["vmIsolation"], "not-attested")


class ProvisioningTests(unittest.TestCase):
    def boot_record(self, **fields):
        return {
            "protocol": PROTOCOL, "session": SESSION.hex(), "key": KEY.hex(),
            "expiresAt": 1100, **fields,
        }

    def load_record(self, value, **metadata):
        data = json.dumps(value).encode()
        info = types.SimpleNamespace(
            st_mode=stat.S_IFREG | 0o600, st_uid=0, st_size=len(data),
            st_mtime_ns=1, st_ctime_ns=1,
        )
        for key, item in metadata.items():
            setattr(info, key, item)
        with mock.patch.object(guest_probe.os, "open", return_value=42) as opened, \
             mock.patch.object(guest_probe.os, "fstat", return_value=info), \
             mock.patch.object(guest_probe.os, "read", return_value=data), \
             mock.patch.object(guest_probe.os, "close") as closed:
            try:
                return guest_probe.read_boot_config(Path("/owned-fixture"), now=1000)
            finally:
                self.assertTrue(opened.call_args.args[1] & os.O_NOFOLLOW)
                closed.assert_called_once_with(42)

    def test_accepts_only_fresh_private_root_owned_boot_identity(self):
        self.assertEqual(self.load_record(self.boot_record()), (KEY, SESSION, 1100))
        for metadata in [{"st_uid": 1000}, {"st_mode": stat.S_IFREG | 0o644},
                         {"st_mode": stat.S_IFDIR | 0o600}, {"st_size": 1025}]:
            with self.subTest(metadata=metadata), self.assertRaises(ProbeRejected):
                self.load_record(self.boot_record(), **metadata)

    def test_expired_overlong_boolean_or_extra_boot_records_fail(self):
        for fields in [{"expiresAt": 1000}, {"expiresAt": 1301}, {"expiresAt": True},
                       {"key": "bad"}, {"session": "bad"}, {"target": "forbidden"}]:
            with self.subTest(fields=fields), self.assertRaises(ProbeRejected):
                self.load_record(self.boot_record(**fields))

    def test_importing_guest_does_not_create_a_socket(self):
        import importlib
        with mock.patch.object(guest_probe.socket, "socket", side_effect=AssertionError("No implicit probe")):
            importlib.reload(guest_probe)

    def test_main_has_no_tcp_fallback(self):
        with mock.patch.object(guest_probe, "read_boot_config", return_value=(KEY, SESSION, time.time() + 20)), \
             mock.patch.object(guest_probe.socket, "socket", side_effect=OSError("Unavailable")) as create:
            with self.assertRaises(OSError):
                guest_probe.main()
            create.assert_called_once_with(socket.AF_VSOCK, socket.SOCK_STREAM, 0)


if __name__ == "__main__":
    unittest.main()