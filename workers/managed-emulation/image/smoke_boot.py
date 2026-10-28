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
        "native": {"CLINE_MANAGED_CREDENTIAL_ACCEPTED_V1": 1, "CLINE_MANAGED_PROBE_UNRESOLVED_V1": 1},
    }
    if credential_case not in states:
        raise ValueError("Unknown owned credential fixture")
    markers = {"CLINE_MANAGED_CREDENTIAL_ABSENT_V1", "CLINE_MANAGED_BOOT_REJECTED_V1", "CLINE_MANAGED_CREDENTIAL_ACCEPTED_V1", "CLINE_MANAGED_PROBE_UNRESOLVED_V1", "CLINE_MANAGED_PROBE_EXITED_V1"}
    if any(text.count(marker) != states[credential_case].get(marker, 0) for marker in markers):
        raise ValueError("Guest credential/termination scope mismatch")
    return receipt


def validate_engine_log(data, engine, expected_bundle=None):
    text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", data.decode("utf-8", errors="replace"))
    marker = "CLINE_MANAGED_ENGINE_OWNED_V1 "
    lines = [line.strip() for line in text.splitlines() if line.startswith(marker)]
    if len(lines) != 1 or "CLINE_MANAGED_ENGINE_FAILED_V1" in text:
        raise ValueError("Actual owned engine receipt missing or failed")
    def unique(pairs):
        value = {}
        for key,item in pairs:
            if key in value:
                raise ValueError("Duplicate owned engine evidence")
            value[key] = item
        return value
    value = json.loads(lines[0][len(marker):], object_pairs_hook=unique)
    arches = {"qiling":["x86_64","arm32","arm64"],"unidbg":["arm32","arm64"],"rnidbg":["arm64"],"speakeasy":["x86_64"]}
    expected = {"schema":1,"engine":engine,"architectures":arches[engine],"checks":{"qiling":12,"unidbg":10,"rnidbg":5,"speakeasy":4}[engine],"ownedFixtures":"passed","engineReadiness":"not-tested","vmIsolation":"not-attested"}
    if not isinstance(value,dict) or type(value.get("schema")) is not int or type(value.get("checks")) is not int or not isinstance(value.get("bundleSha256"),str) or set(value) != set(expected) | {"bundleSha256"} or any(value[k] != v for k,v in expected.items()) or not re.fullmatch("[0-9a-f]{64}",value["bundleSha256"]):
        raise ValueError("Owned engine evidence scope mismatch")
    if expected_bundle is not None and value["bundleSha256"] != expected_bundle:
        raise ValueError("Owned engine bundle/image binding mismatch")
    return value


def run(image, output, uefi=False, credential_case="absent", native_generator=None, owned_engine=None):
    if owned_engine not in (None, "qiling", "unidbg", "rnidbg", "speakeasy") or (owned_engine and credential_case != "absent"):
        raise ValueError("Fixed owned engine boot required")
    image = image.resolve(strict=True)
    command = ["qemu-system-x86_64", "-accel", "tcg", "-machine", "pc", "-m", "2048" if owned_engine else "1024", "-smp", "1", "-nic", "none", "-nodefaults", "-display", "none", "-serial", "stdio", "-monitor", "none", "-no-reboot", "-cdrom", str(image), "-boot", "d"]
    with tempfile.TemporaryDirectory(prefix="cline-owned-boot-") as private:
        if credential_case not in {"absent", "expired", "valid", "native"}:
            raise ValueError("Unknown owned credential fixture")
        if credential_case == "native":
            if native_generator is None:
                raise ValueError("Owned native generator required")
            generator = native_generator.resolve(strict=True)
            generated = subprocess.run([str(generator), private], check=False, capture_output=True, timeout=30)
            if (generated.returncode != 0 or generated.stderr
                    or generated.stdout != b"Owned private boot media written; no VM or readiness established.\n"):
                # Never echo private material, raw child errors or command input.
                raise ValueError("Owned native provisioning failed")
            media = Path(private) / "boot.iso"
            info = media.lstat()
            if not media.is_file() or media.is_symlink() or info.st_size != 22 * 2048 or info.st_mode & 0o077:
                raise ValueError("Owned native media rejected")
            command.extend(["-drive", f"file={media},media=cdrom,readonly=on,format=raw,index=3"])
        elif credential_case != "absent":
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
        data, deadline = bytearray(), time.monotonic() + (300 if owned_engine else 120)
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
        engine_evidence = None
        if owned_engine:
            manifest_bytes = (image.parent / "image-manifest.json").read_bytes()
            if len(manifest_bytes) > 1024*1024:
                raise ValueError("Owned image manifest budget")
            manifest = json.loads(manifest_bytes)
            if manifest.get("ownedEngine") != owned_engine or manifest.get("artifacts",{}).get("inert-guest.iso",{}).get("sha256") != hashlib.sha256(image.read_bytes()).hexdigest():
                raise ValueError("Owned engine image identity mismatch")
            bundle = manifest.get("ownedEngineBundleSha256")
            if not isinstance(bundle,str) or not re.fullmatch("[0-9a-f]{64}",bundle):
                raise ValueError("Owned engine bundle identity absent")
            engine_evidence = validate_engine_log(data, owned_engine, bundle)

        return {"schema": 1, "boot": "uefi" if uefi else "bios", "backend": "qemu-tcg-no-nic", "imageSha256": hashlib.sha256(image.read_bytes()).hexdigest(), "ownedBoot": "passed", "ownedEngine": owned_engine, "ownedEngineEvidence": engine_evidence, "credentialCase": credential_case, "credentialResult": {"absent": "denied", "expired": "denied", "valid": "owned-fixture-provisioned-exchange-unresolved", "native": "native-private-media-provisioned-exchange-unresolved"}[credential_case], **receipt}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", type=Path, required=True)
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--uefi", action="store_true")
    parser.add_argument("--credential-case", choices=["absent", "expired", "valid", "native"], default="absent")
    parser.add_argument("--native-media-generator", type=Path)
    parser.add_argument("--owned-engine", choices=["qiling", "unidbg", "rnidbg", "speakeasy"])
    args = parser.parse_args()
    result = run(args.image, args.log, args.uefi, args.credential_case, args.native_media_generator, args.owned_engine)
    args.receipt.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
