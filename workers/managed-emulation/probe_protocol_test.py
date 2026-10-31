"""Owned protocol fixtures. Socketpair results are NOT Hyper-V/VM evidence."""
import io
import json
import os
from pathlib import Path
import socket
import stat
import struct
import threading
import tempfile
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
            st_mtime_ns=1, st_ctime_ns=1, st_nlink=1, st_dev=1, st_ino=2,
        )
        for key, item in metadata.items():
            setattr(info, key, item)
        with mock.patch.object(guest_probe, "_open_private_boot_record", return_value=42), \
             mock.patch.object(guest_probe.os, "fstat", return_value=info), \
             mock.patch.object(guest_probe.os, "read", return_value=data), \
             mock.patch.object(guest_probe.os, "close") as closed:
            try:
                return guest_probe.read_boot_config(now=1000)
            finally:
                closed.assert_called_once_with(42)

    def test_accepts_only_fresh_private_root_owned_boot_identity(self):
        self.assertEqual(self.load_record(self.boot_record()), (KEY, SESSION, 1100))
        for metadata in [{"st_uid": 1000}, {"st_mode": stat.S_IFREG | 0o644},
                         {"st_mode": stat.S_IFDIR | 0o600}, {"st_size": 1025}, {"st_nlink": 2}]:
            with self.subTest(metadata=metadata), self.assertRaises(ProbeRejected):
                self.load_record(self.boot_record(), **metadata)

    def test_expired_overlong_boolean_or_extra_boot_records_fail(self):
        for fields in [{"expiresAt": 1000}, {"expiresAt": 1301}, {"expiresAt": True},
                       {"key": "bad"}, {"session": "bad"}, {"target": "forbidden"}]:
            with self.subTest(fields=fields), self.assertRaises(ProbeRejected):
                self.load_record(self.boot_record(**fields))


    def directory(self, mode=0o755, uid=0):
        return types.SimpleNamespace(st_mode=stat.S_IFDIR | mode, st_uid=uid)

    def test_every_boot_parent_is_pinned_without_following_links(self):
        metadata = [self.directory(), self.directory(), self.directory(0o700)]
        with mock.patch.object(guest_probe.os, "open", side_effect=[39, 40, 41, 42]) as opened, \
             mock.patch.object(guest_probe.os, "fstat", side_effect=metadata), \
             mock.patch.object(guest_probe.os, "close") as closed:
            self.assertEqual(guest_probe._open_private_boot_record(), 42)
            self.assertEqual([call.args[0] for call in opened.call_args_list], ["/", "run", "cline-managed-probe", "boot.json"])
            self.assertEqual([call.kwargs["dir_fd"] for call in opened.call_args_list], [None, 39, 40, 41])
            for index, call in enumerate(opened.call_args_list):
                self.assertTrue(call.args[1] & os.O_NOFOLLOW)
                self.assertTrue(call.args[1] & os.O_NONBLOCK)
                if index < 3:
                    self.assertTrue(call.args[1] & os.O_DIRECTORY)
            self.assertEqual(closed.call_args_list, [mock.call(41), mock.call(40), mock.call(39)])

    def test_writable_foreign_and_non_private_parent_directories_are_rejected(self):
        for index in range(3):
            for bad in [self.directory(uid=1000), self.directory(0o777),
                        types.SimpleNamespace(st_mode=stat.S_IFREG | 0o700, st_uid=0)]:
                metadata = [self.directory(), self.directory(), self.directory(0o700)]
                metadata[index] = bad
                with self.subTest(index=index, bad=bad), \
                     mock.patch.object(guest_probe.os, "open", side_effect=[39, 40, 41, 42]) as opened, \
                     mock.patch.object(guest_probe.os, "fstat", side_effect=metadata), \
                     mock.patch.object(guest_probe.os, "close") as closed:
                    with self.assertRaises(ProbeRejected):
                        guest_probe._open_private_boot_record()
                    self.assertEqual(opened.call_count, index + 1)
                    self.assertEqual(closed.call_count, index + 1)
        with mock.patch.object(guest_probe.os, "open", side_effect=[39, 40, 41]), \
             mock.patch.object(guest_probe.os, "fstat", side_effect=[self.directory(), self.directory(), self.directory(0o755)]), \
             mock.patch.object(guest_probe.os, "close"):
            with self.assertRaises(ProbeRejected):
                guest_probe._open_private_boot_record()

    def test_parent_open_failures_close_only_owned_descriptors(self):
        for failure in range(4):
            opens = [39, 40, 41, 42][:failure] + [OSError("No follow")]
            with self.subTest(failure=failure), \
                 mock.patch.object(guest_probe.os, "open", side_effect=opens), \
                 mock.patch.object(guest_probe.os, "fstat", side_effect=[self.directory(), self.directory(), self.directory(0o700)]), \
                 mock.patch.object(guest_probe.os, "close") as closed:
                with self.assertRaises(OSError):
                    guest_probe._open_private_boot_record()
                self.assertEqual(closed.call_args_list, [mock.call(fd) for fd in reversed([39,40,41][:failure])])

    def test_boot_file_metadata_changes_are_rejected_and_descriptor_closed(self):
        data = json.dumps(self.boot_record()).encode()
        before = dict(st_mode=stat.S_IFREG | 0o600, st_uid=0, st_size=len(data),
                      st_nlink=1, st_dev=1, st_ino=2, st_mtime_ns=1, st_ctime_ns=1)
        for field in before:
            after = {**before, field: before[field] + 1}
            with self.subTest(field=field), \
                 mock.patch.object(guest_probe, "_open_private_boot_record", return_value=42), \
                 mock.patch.object(guest_probe.os, "fstat", side_effect=[types.SimpleNamespace(**before), types.SimpleNamespace(**after)]), \
                 mock.patch.object(guest_probe.os, "read", return_value=data), \
                 mock.patch.object(guest_probe.os, "close") as closed:
                with self.assertRaises(ProbeRejected):
                    guest_probe.read_boot_config(now=1000)
                closed.assert_called_once_with(42)


    def real_owned_fixture(self, alteration=None):
        # Use actual openat/O_NOFOLLOW/FIFO behavior. Only ownership is synthesized:
        # unprivileged CI cannot create root-owned fixtures, so this is not root/VM proof.
        real_open, real_fstat = os.open, os.fstat
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run = root / "run"
            run.mkdir(mode=0o755)
            private = run / "cline-managed-probe"
            private.mkdir(mode=0o700)
            record = private / "boot.json"
            record.write_text(json.dumps(self.boot_record()))
            record.chmod(0o600)
            if alteration:
                alteration(root, run, private, record)

            def fixture_open(path, flags, **kwargs):
                return real_open(root if path == "/" and kwargs.get("dir_fd") is None else path, flags, **kwargs)

            def fixture_owner(descriptor):
                info = real_fstat(descriptor)
                fields = ("st_mode", "st_size", "st_nlink", "st_dev", "st_ino", "st_mtime_ns", "st_ctime_ns")
                return types.SimpleNamespace(**{field: getattr(info, field) for field in fields}, st_uid=0)

            with mock.patch.object(guest_probe.os, "open", side_effect=fixture_open), \
                 mock.patch.object(guest_probe.os, "fstat", side_effect=fixture_owner):
                return guest_probe.read_boot_config(now=1000)

    def test_actual_descriptor_relative_boot_file_read(self):
        self.assertEqual(self.real_owned_fixture(), (KEY, SESSION, 1100))

    def test_kernel_rejects_symlinked_parent_and_leaf(self):
        def linked_parent(root, run, private, record):
            private.rename(root / "moved")
            private.symlink_to(root / "moved", target_is_directory=True)

        def linked_leaf(root, run, private, record):
            record.rename(private / "moved.json")
            record.symlink_to(private / "moved.json")

        for alteration in (linked_parent, linked_leaf):
            with self.subTest(alteration=alteration.__name__), self.assertRaises(OSError):
                self.real_owned_fixture(alteration)

    def test_actual_fifo_is_rejected_without_waiting_for_a_writer(self):
        def fifo(root, run, private, record):
            record.unlink()
            os.mkfifo(record, 0o600)
        with self.assertRaises(ProbeRejected):
            self.real_owned_fixture(fifo)

    def test_actual_hardlinked_record_and_writable_directory_are_rejected(self):
        def hardlink(root, run, private, record):
            os.link(record, private / "linked.json")

        def writable(root, run, private, record):
            private.chmod(0o777)

        for alteration in (hardlink, writable):
            with self.subTest(alteration=alteration.__name__), self.assertRaises(ProbeRejected):
                self.real_owned_fixture(alteration)

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