"""Development-only, authenticated inert probe. Not an engine executor or VM attestation.

The lifecycle broker must provision a fresh session/key into the guest privately.
There is deliberately no shell, file-transfer, HTTP, or target-execution operation.
"""
import hashlib
import hmac
import json
import re
import struct
import time

PROTOCOL = "cline-managed-inert-probe/v1"
DOMAIN = (PROTOCOL + "\0").encode("ascii")
MAX_FRAME = 4096
MAX_PAYLOAD = 1024
FIXTURE = b"cline-managed-owned-inert-fixture/v1\n"
FIXTURE_SHA256 = hashlib.sha256(FIXTURE).hexdigest()


class ProbeRejected(ValueError):
    pass


def exact_hex(value, size):
    if not isinstance(value, str) or not re.fullmatch("[0-9a-f]{" + str(size * 2) + "}", value):
        raise ProbeRejected("Invalid protocol identity")
    return bytes.fromhex(value)


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ProbeRejected("Duplicate protocol field")
        value[key] = item
    return value


def parse_json(data):
    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=unique_object)
    except (ValueError, UnicodeError, RecursionError) as error:
        raise ProbeRejected("Invalid protocol JSON") from error


def encode_frame(key, session, sequence, payload):
    if len(key) != 32 or len(session) != 16 or sequence not in (1, 2):
        raise ProbeRejected("Invalid protocol identity")
    body = json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    if len(body) > MAX_PAYLOAD:
        raise ProbeRejected("Payload budget")
    mac = hmac.digest(key, DOMAIN + session + bytes([sequence]) + body, "sha256")
    envelope = json.dumps({
        "protocol": PROTOCOL, "session": session.hex(), "sequence": sequence,
        "payload": body.hex(), "mac": mac.hex(),
    }, separators=(",", ":")).encode("ascii")
    if len(envelope) > MAX_FRAME:
        raise ProbeRejected("Frame budget")
    return struct.pack(">I", len(envelope)) + envelope


def receive_exact(connection, length, deadline):
    result = bytearray()
    while len(result) < length:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ProbeRejected("Probe deadline")
        connection.settimeout(remaining)
        part = connection.recv(length - len(result))
        if not part:
            raise ProbeRejected("Truncated probe")
        result.extend(part)
    return bytes(result)


def receive_frame(connection, key, session, sequence, deadline):
    size = struct.unpack(">I", receive_exact(connection, 4, deadline))[0]
    if not 1 <= size <= MAX_FRAME:
        raise ProbeRejected("Frame budget")
    value = parse_json(receive_exact(connection, size, deadline))
    if not isinstance(value, dict) or set(value) != {"protocol", "session", "sequence", "payload", "mac"}:
        raise ProbeRejected("Exact envelope required")
    if (value["protocol"] != PROTOCOL or value["session"] != session.hex()
            or type(value["sequence"]) is not int or value["sequence"] != sequence):
        raise ProbeRejected("Probe identity mismatch")
    body = exact_hex(value["payload"], len(value["payload"]) // 2) if isinstance(value["payload"], str) else None
    if body is None or len(body) > MAX_PAYLOAD:
        raise ProbeRejected("Payload budget")
    supplied = exact_hex(value["mac"], 32)
    expected = hmac.digest(key, DOMAIN + session + bytes([sequence]) + body, "sha256")
    if not hmac.compare_digest(supplied, expected):
        raise ProbeRejected("Probe authentication failed")
    return parse_json(body)


def serve_one(connection, key, session, deadline):
    """One request, one result, then close. A connection is never an execution authority."""
    request = receive_frame(connection, key, session, 1, deadline)
    if (not isinstance(request, dict) or set(request) != {"operation", "challenge"}
            or request["operation"] != "owned-probe"):
        raise ProbeRejected("Only the inert owned probe is implemented")
    exact_hex(request["challenge"], 32)
    response = {
        "operation": "owned-probe-result",
        "challenge": request["challenge"],
        "fixtureSha256": FIXTURE_SHA256,
        "execution": "owned-fixture-only",
        "vmIsolation": "not-attested",
        "engineReadiness": "not-tested",
    }
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ProbeRejected("Probe deadline")
    connection.settimeout(remaining)
    connection.sendall(encode_frame(key, session, 2, response))