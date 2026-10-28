"""Boot ONLY the owned development image under networkless QEMU/TCG.

This is not Hyper-V, hardware containment, or framework installation acceptance.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import selectors
import re
import shutil
import signal
import subprocess
import tempfile
import time

MAX_LOG = 1024 * 1024


def validate_boot_log(data, status, credential_case="absent"):
    # Preserve raw evidence; strip terminal CSI decoration only for parsing.
    text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", data.decode("utf-8", errors="replace"))
    marker = "CLINE_MANAGED_INERT_BOOT_V1 "
    lines = [line.strip() for line in text.splitlines() if line.startswith(marker)]
    if status != 0 or len(lines) != 1:
        raise ValueError("Owned guest failed boot")
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("Duplicate guest receipt field")
            value[key] = item
        return value
    receipt = json.loads(lines[0][len(marker):], object_pairs_hook=unique)
    expected = {"fixtureSha256": hashlib.sha256(b"cline-managed-owned-inert-fixture/v1\n").hexdigest(), "vmIsolation": "not-attested", "engineReadiness": "not-tested", "hypervExchange": "not-tested"}
    if receipt != expected:
        raise ValueError("Guest receipt scope mismatch")
    states = {
        "absent": {"CLINE_MANAGED_CREDENTIAL_ABSENT_V1": 1},
        "expired": {"CLINE_MANAGED_BOOT_REJECTED_V1": 1},
        "valid": {"CLINE_MANAGED_CREDENTIAL_ACCEPTED_V1": 1, "CLINE_MANAGED_PROBE_UNRESOLVED_V1": 1},
    }
    if credential_case not in states:
        raise ValueError("Unknown owned credential fixture")
    markers = {"CLINE_MANAGED_CREDENTIAL_ABSENT_V1", "CLINE_MANAGED_BOOT_REJECTED_V1", "CLINE_MANAGED_CREDENTIAL_ACCEPTED_V1", "CLINE_MANAGED_PROBE_UNRESOLVED_V1", "CLINE_MANAGED_PROBE_EXITED_V1"}
    if any(text.count(marker) != states[credential_case].get(marker, 0) for marker in markers):
        raise ValueError("Guest credential/termination scope mismatch")
    return receipt


def run(image, output, uefi=False, credential_case="absent"):
    image = image.resolve(strict=True)
    command = ["qemu-system-x86_64", "-accel", "tcg", "-machine", "pc", "-m", "1024", "-smp", "1", "-nic", "none", "-nodefaults", "-display", "none", "-serial", "stdio", "-monitor", "none", "-no-reboot", "-cdrom", str(image), "-boot", "d"]
    with tempfile.TemporaryDirectory(prefix="cline-owned-boot-") as private:
        if credential_case not in {"absent", "expired", "valid"}:
            raise ValueError("Unknown owned credential fixture")
        if credential_case != "absent":
            media_root = Path(private) / "media"
            media_root.mkdir(mode=0o700)
            # PUBLIC fixture identities only, never production boot credentials.
            record = {"protocol": "cline-managed-inert-probe/v1", "session": bytes(range(16)).hex(), "key": bytes(range(32)).hex(), "expiresAt": 0 if credential_case == "expired" else int(time.time()) + 180}
            descriptor = os.open(media_root / "boot.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "w") as stream:
                json.dump(record, stream)
            media = Path(private) / "fixture.iso"
            subprocess.run(["xorriso", "-as", "mkisofs", "-quiet", "-R", "-V", "CLINEBOOT", "-o", str(media), str(media_root)], check=True, capture_output=True, timeout=30)
            command.extend(["-drive", f"file={media},media=cdrom,readonly=on,format=raw,index=3"])
        if uefi:
            code = Path("/usr/share/OVMF/OVMF_CODE_4M.fd")
            variables = Path("/usr/share/OVMF/OVMF_VARS_4M.fd")
            if not code.is_file() or not variables.is_file():
                raise ValueError("Reviewed CI UEFI firmware absent")
            writable = Path(private) / "variables.fd"
            shutil.copyfile(variables, writable)
            command.extend(["-drive", f"if=pflash,format=raw,unit=0,readonly=on,file={code}", "-drive", f"if=pflash,format=raw,unit=1,file={writable}"])
        child = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True)
        data, deadline = bytearray(), time.monotonic() + 120
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(child.stdout, selectors.EVENT_READ)
                while selector.get_map():
                    if time.monotonic() >= deadline:
                        raise ValueError("Owned guest boot deadline")
                    for key, _ in selector.select(0.1):
                        chunk = os.read(key.fd, 65536)
                        if not chunk:
                            selector.unregister(key.fileobj)
                        else:
                            data.extend(chunk)
                            if len(data) > MAX_LOG:
                                raise ValueError("Owned guest boot log budget")
            status = child.wait(timeout=max(0.001, deadline - time.monotonic()))
        finally:
            if child.poll() is None:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait(timeout=5)
            child.stdout.close()
            output.write_bytes(data)
        receipt = validate_boot_log(data, status, credential_case)
        return {"schema": 1, "boot": "uefi" if uefi else "bios", "backend": "qemu-tcg-no-nic", "imageSha256": hashlib.sha256(image.read_bytes()).hexdigest(), "ownedBoot": "passed", "credentialCase": credential_case, "credentialResult": {"absent": "denied", "expired": "denied", "valid": "owned-fixture-provisioned-exchange-unresolved"}[credential_case], **receipt}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", type=Path, required=True)
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--uefi", action="store_true")
    parser.add_argument("--credential-case", choices=["absent", "expired", "valid"], default="absent")
    args = parser.parse_args()
    result = run(args.image, args.log, args.uefi, args.credential_case)
    args.receipt.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
