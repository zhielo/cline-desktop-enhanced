"""Build a development inert RAM guest from pinned inputs, without host extraction.

No VM provisioning, release publication, engine installation or app route exists
here. Debian package maintainer scripts and guest programs never run on the host.
"""
import argparse
from dataclasses import dataclass
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import sys
import subprocess
import tarfile
import tempfile
import zipfile

HERE = Path(__file__).resolve().parent
MAX_INPUT = 512 * 1024 * 1024
MAX_FILE = 64 * 1024 * 1024
MAX_ENTRIES = 40_000


@dataclass(frozen=True)
class Node:
    kind: str
    mode: int
    data: bytes = b""


def name(value):
    if not isinstance(value, str) or not value or value.startswith("/") or any(ord(c) < 32 for c in value) or "\\" in value:
        raise ValueError("Unsafe archive path")
    parts = [part for part in value.split("/") if part != "."]
    if any(part in ("", "..") for part in parts) or len(value.encode()) > 1024:
        raise ValueError("Unsafe archive path")
    return "/".join(parts) or "."


def link_target(path, target):
    if not target or len(target.encode()) > 1024 or any(ord(c) < 32 for c in target) or "\\" in target:
        raise ValueError("Unsafe archive link")
    parts = [] if target.startswith("/") else path.split("/")[:-1]
    for part in target.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            if not parts:
                raise ValueError("Escaping archive link")
            parts.pop()
        else:
            parts.append(part)
    return "/".join(parts) or "."


def archive(data):
    if len(data) > MAX_INPUT:
        raise ValueError("Archive input budget")
    nodes, hardlinks, total = {}, {}, 0
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as stream:
        for member in stream:
            path = name(member.name.rstrip("/"))
            if path in nodes or path in hardlinks or len(nodes) + len(hardlinks) >= MAX_ENTRIES:
                raise ValueError("Duplicate archive member or count budget")
            mode = member.mode & 0o755  # No setuid/setgid or group/world-writable contents.
            if member.isdir():
                nodes[path] = Node("directory", mode)
            elif member.isfile():
                total += member.size
                if member.size > MAX_FILE or total > MAX_INPUT:
                    raise ValueError("Archive content budget")
                body = stream.extractfile(member).read(MAX_FILE + 1)
                if len(body) != member.size:
                    raise ValueError("Truncated archive member")
                nodes[path] = Node("file", mode, body)
            elif member.issym():
                link_target(path, member.linkname)
                nodes[path] = Node("symlink", 0o777, member.linkname.encode())
            elif member.islnk():
                hardlinks[path] = (name(member.linkname), mode)
            else:
                raise ValueError("Special archive member forbidden")
    for path, (target, mode) in hardlinks.items():
        visited = {path}
        while target in hardlinks:
            if target in visited:
                raise ValueError("Archive hardlink cycle")
            visited.add(target)
            target = hardlinks[target][0]
        source = nodes.get(target)
        if source is None or source.kind != "file":
            raise ValueError("Archive hardlink target rejected")
        nodes[path] = Node("file", mode, source.data)
    return nodes


def canonical(path, tree):
    # Resolve virtual-image parents only. Never follows a host filesystem link.
    for _ in range(32):
        parts, changed = path.split("/"), False
        for index in range(1, len(parts)):
            parent = "/".join(parts[:index])
            node = tree.get(parent)
            if node and node.kind == "symlink":
                target = link_target(parent, node.data.decode())
                path = "/".join(([target] if target != "." else []) + parts[index:])
                changed = True
                break
            if node and node.kind != "directory":
                raise ValueError("Non-directory image parent")
        if not changed:
            return name(path)
    raise ValueError("Image link cycle")


def cpio(tree):
    # The Linux initramfs newc format: fixed root ownership and timestamps.
    expanded = {".": Node("directory", 0o755), **tree}
    for path in list(expanded):
        name(path)
        parts = path.split("/")
        for index in range(1, len(parts)):
            parent = "/".join(parts[:index])
            previous = expanded.setdefault(parent, Node("directory", 0o755))
            if previous.kind != "directory":
                raise ValueError("Linked/non-directory CPIO parent")
    if len(expanded) > MAX_ENTRIES:
        raise ValueError("CPIO member budget")
    if sum(len(node.data) for node in expanded.values()) > MAX_INPUT:
        raise ValueError("CPIO content budget")
    output = io.BytesIO()
    def emit(path, node, inode):
        body = node.data if node.kind != "directory" else b""
        mode = {"file": stat.S_IFREG, "directory": stat.S_IFDIR, "symlink": stat.S_IFLNK}[node.kind] | (0o777 if node.kind == "symlink" else node.mode & 0o755)
        encoded = path.encode() + b"\0"
        fields = [inode, mode, 0, 0, 2 if node.kind == "directory" else 1, 0, len(body), 0, 0, 0, 0, len(encoded), 0]
        header = b"070701" + b"".join(f"{value:08x}".encode() for value in fields)
        output.write(header + encoded)
        output.write(b"\0" * (-(len(header) + len(encoded)) % 4))
        output.write(body)
        output.write(b"\0" * (-len(body) % 4))
    for inode, path in enumerate(sorted(expanded, key=lambda p: (p.count("/"), p)), 1):
        emit(path, expanded[path], inode)
    emit("TRAILER!!!", Node("file", 0), len(expanded) + 1)
    return gzip.compress(output.getvalue(), compresslevel=6, mtime=0)


def package(path, expected):
    if path.stat().st_size != expected["size"]:
        raise ValueError("Pinned package size")
    data = path.read_bytes()
    if len(data) != expected["size"] or hashlib.sha256(data).hexdigest() != expected["sha256"]:
        raise ValueError("Pinned package integrity")
    if data[:8] != b"!<arch>\n":
        raise ValueError("Debian package container")
    offset, selected = 8, None
    while offset < len(data):
        header = data[offset:offset+60]
        if len(header) != 60 or header[58:60] != b"`\n":
            raise ValueError("Debian package header")
        size = int(header[48:58].decode().strip())
        start = offset + 60
        body = data[start:start+size]
        if len(body) != size:
            raise ValueError("Debian package truncation")
        label = header[:16].decode().strip().rstrip("/")
        if label.startswith("data.tar."):
            if selected is not None:
                raise ValueError("Duplicate Debian data")
            selected = body
        offset = start + size + size % 2
    if selected is None:
        raise ValueError("Missing Debian data")
    return archive(selected)


def run_tool(command, **options):
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, **options)
    if result.returncode:
        # Reviewed public build inputs only, never per-job credentials/targets.
        print(result.stdout[-16384:].decode(errors="replace"), file=sys.stderr)
        raise ValueError("Reviewed image tool failed")
    return result


def modules(kernel, release):
    prefix = "lib/modules/" + release + "/"
    with tempfile.TemporaryDirectory(prefix="cline-reviewed-module-index-") as private:
        root = Path(private)
        for path, node in kernel.items():
            if path.startswith(prefix) and node.kind == "file":
                destination = root / path
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(node.data)
        run_tool(["depmod", "-b", str(root), release], timeout=60)
        base = root / prefix
        dependencies = {}
        for line in (base / "modules.dep").read_text().splitlines():
            key, following = line.split(":", 1)
            dependencies[key] = following.split()
        wanted = {"vsock", "hv_sock", "hv_vmbus", "hv_storvsc", "ata_piix", "sr_mod", "isofs"}
        names = {Path(path).name.split(".ko")[0].replace("-", "_"): path for path in dependencies}
        if not wanted <= names.keys():
            raise ValueError("Required guest driver absent: " + ",".join(sorted(wanted - names.keys())))
        retained = set()
        def retain(path):
            if path in retained:
                return
            retained.add(path)
            for dependency in dependencies[path]:
                retain(dependency)
        for module in sorted(wanted):
            retain(names[module])
        result = {"usr/" + prefix + path: kernel[prefix + path] for path in retained}
        text = "".join(path + ":" + (" " + " ".join(dependencies[path]) if dependencies[path] else "") + "\n" for path in sorted(retained))
        result["usr/" + prefix + "modules.dep"] = Node("file", 0o644, text.encode())
        for label in ("modules.builtin", "modules.builtin.modinfo"):
            source = base / label
            if source.is_file():
                result["usr/" + prefix + label] = Node("file", 0o644, source.read_bytes())
        return result


def owned_bundle(original, engine):
    prefix = "opt/cline-engine/"
    selected = {path: node for path,node in original.items() if path.startswith(prefix)}
    required = {prefix+"bundle.json", prefix+"engine", prefix+"selftest.py", prefix+"env/bin/python"}
    if not required <= selected.keys() or selected[prefix+"engine"].data != (engine+"\n").encode():
        raise ValueError("Owned engine bundle absent or mismatched")
    raw = selected[prefix+"bundle.json"].data
    if not 1 <= len(raw) <= 4*1024*1024:
        raise ValueError("Owned bundle manifest budget")
    def unique(pairs):
        value = {}
        for key,item in pairs:
            if key in value:
                raise ValueError("Duplicate engine manifest field")
            value[key] = item
        return value
    manifest = json.loads(raw, object_pairs_hook=unique)
    if not isinstance(manifest,dict) or set(manifest) != {"schema","engine","scope","files"} or type(manifest["schema"]) is not int or manifest["schema"] != 1 or manifest["engine"] != engine or manifest["scope"] != "development-owned-guest-tests-only" or not isinstance(manifest["files"],dict):
        raise ValueError("Owned engine manifest mismatch")
    if not 1 <= len(manifest["files"]) <= 20_000:
        raise ValueError("Owned engine manifest count budget")
    observed = {path[len(prefix):] for path,node in selected.items() if node.kind != "directory"}
    if observed != set(manifest["files"]) | {"bundle.json"}:
        raise ValueError("Unsealed exported runtime file")
    total = 0
    for label, entry in manifest["files"].items():
        if not isinstance(label,str) or not label or label.startswith("/") or any(part in ("", ".", "..") for part in label.split("/")) or "\\" in label or "\x00" in label or not isinstance(entry,dict):
            raise ValueError("Unsafe exported runtime entry")
        node = selected[prefix+label]
        if entry.get("kind") == "file" and set(entry) == {"kind", "size", "sha256"}:
            size, digest = entry["size"], entry["sha256"]
            if type(size) is not int or not 0 <= size <= 64*1024**2 or not isinstance(digest,str) or not re.fullmatch("[0-9a-f]{64}", digest):
                raise ValueError("Exported runtime file schema")
            total += size
            if total > 384*1024**2 or node.kind != "file" or len(node.data) != size or hashlib.sha256(node.data).hexdigest() != digest:
                raise ValueError("Exported runtime file mismatch/budget")
        elif entry.get("kind") == "symlink" and set(entry) == {"kind", "target"}:
            target = entry["target"]
            if not isinstance(target,str) or not target or len(target) > 1024 or "\x00" in target or node.kind != "symlink" or node.data != target.encode():
                raise ValueError("Exported runtime link mismatch")
        else:
            raise ValueError("Exported runtime entry type")
    # Build dependencies cannot replace the trusted fixed acceptance program or
    # repository collectors and then certify themselves with a generated hash.
    repository = HERE.parents[2]
    sources = {"selftest.py": HERE.parent/"engines/selftest.py"}
    if engine == "qiling":
        sources["qiling_runner.py"] = repository/"workers/emulation/qiling_runner.py"
    elif engine == "speakeasy":
        sources.update({"collector.py": repository/"workers/re-analysis/collector.py", "owned_pe.py": repository/"workers/re-analysis/collector.test.py"})
    for label, source in sources.items():
        node = selected.get(prefix+label)
        expected = source.read_bytes()
        entry = manifest["files"].get(label,{})
        if node is None or node.kind != "file" or node.data != expected or entry.get("sha256") != hashlib.sha256(expected).hexdigest():
            raise ValueError("Owned acceptance source replaced")
    return selected


def owned_native_evidence(tree, engine):
    """Retain sealed build metadata, not an attestation or execution receipt."""
    prefix = "opt/cline-engine/"
    node = tree.get(prefix+"native-build.json")
    if engine != "unidbg":
        if node is not None:
            raise ValueError("Unexpected native build record")
        return None
    if node is None or node.kind != "file" or not 1 <= len(node.data) <= 64*1024:
        raise ValueError("Native build record absent/type/budget")
    def unique(pairs):
        out = {}
        for key, value in pairs:
            if key in out:
                raise ValueError("Duplicate native build field")
            out[key] = value
        return out
    record = json.loads(node.data, object_pairs_hook=unique)
    fields = {"schema", "scope", "sourceInputs", "patchedBridgeSha256",
              "patchedJnaSha256", "jnaNativeAbi", "jnaNativeApiChecksum",
              "resources", "emulatorExecutedDuringBuild", "engineReadiness"}
    if not isinstance(record, dict) or set(record) != fields or type(record["schema"]) is not int or record["schema"] != 1 or record["scope"] != "development-owned-guest-tests-only" or record["emulatorExecutedDuringBuild"] is not False or record["engineReadiness"] != "not-tested":
        raise ValueError("Native build scope/schema")
    expected = json.loads((HERE.parent/"engines/native-inputs.lock.json").read_bytes())
    # Canonical JSON comparison distinguishes booleans from integer identities.
    if json.dumps(record["sourceInputs"], sort_keys=True) != json.dumps(expected, sort_keys=True):
        raise ValueError("Native build source inputs differ")
    if record["jnaNativeAbi"] != "6.1.2" or record["jnaNativeApiChecksum"] != "147a998f0cbc89681a1ae6c0dd121629":
        raise ValueError("Native build JNA ABI differs")
    def digest(value):
        return isinstance(value, str) and re.fullmatch("[0-9a-f]{64}", value) is not None
    if not all(digest(record[key]) for key in ("patchedBridgeSha256", "patchedJnaSha256")):
        raise ValueError("Native patched source digest")
    resources = record["resources"]
    identities = {
        "jna-5.10.0.jar": "com/sun/jna/linux-x86-64/libjnidispatch.so",
        "unidbg-unicorn2-0.9.9.jar": "natives/linux_64/libunicorn.so",
    }
    dependency_lock = HERE.parents[2]/"workers/emulation/unidbg/dependencies.sha256"
    originals = {Path(label.lstrip("*")).name: sha for sha, label in
                 (line.split(maxsplit=1) for line in dependency_lock.read_text().splitlines())}
    if not isinstance(resources, list) or len(resources) != len(identities):
        raise ValueError("Native resource inventory")
    seen = set()
    for item in resources:
        if not isinstance(item, dict) or set(item) != {"jar", "resource", "originalJarSha256", "rebuiltJarSha256", "nativeSha256"}:
            raise ValueError("Native resource schema")
        jar, label = item["jar"], item["resource"]
        if not isinstance(jar, str) or jar not in identities or jar in seen or label != identities[jar]:
            raise ValueError("Native resource identity")
        seen.add(jar)
        if not all(digest(item[key]) for key in ("originalJarSha256", "rebuiltJarSha256", "nativeSha256")) or item["originalJarSha256"] != originals[jar]:
            raise ValueError("Native original dependency identity")
        sealed = tree.get(prefix+"dependency/"+jar)
        if sealed is None or sealed.kind != "file" or not 1 <= len(sealed.data) <= 64*1024**2 or hashlib.sha256(sealed.data).hexdigest() != item["rebuiltJarSha256"] or item["rebuiltJarSha256"] == item["originalJarSha256"]:
            raise ValueError("Native rebuilt dependency identity")
        with zipfile.ZipFile(io.BytesIO(sealed.data)) as archive:
            entries = archive.infolist()
            if len(entries) > 4096 or len({entry.filename for entry in entries}) != len(entries) or sum(entry.file_size for entry in entries) > 128*1024**2:
                raise ValueError("Native resource archive budget/duplicates")
            resource = archive.getinfo(label)
            if resource.is_dir() or not 1 <= resource.file_size <= 8*1024**2 or hashlib.sha256(archive.read(resource)).hexdigest() != item["nativeSha256"]:
                raise ValueError("Native binary resource mismatch/budget")
    return node.data


def build(rootfs, kernel_path, busybox_path, output, revision, owned_engine=None):
    if not re.fullmatch("[0-9a-f]{40}", revision) or output.exists() or output.is_symlink():
        raise ValueError("New output and exact source revision required")
    if owned_engine not in (None, "qiling", "unidbg", "rnidbg", "speakeasy"):
        raise ValueError("Unknown owned engine")
    lock = json.loads((HERE / "inputs.lock.json").read_text())
    if rootfs.stat().st_size > MAX_INPUT:
        raise ValueError("Rootfs export budget")
    raw = rootfs.read_bytes()
    original = archive(raw)
    tree = {}
    for path, node in original.items():
        runtime = (path.startswith("usr/local/lib/python3.13/") and not any(part in path.split("/") for part in ("site-packages", "ensurepip", "test", "idlelib", "tkinter", "turtledemo", "__pycache__")) and not path.endswith(".pyc"))
        libraries = path.startswith("usr/lib/x86_64-linux-gnu/") and (node.kind == "directory" or ".so" in Path(path).name)
        if runtime or libraries or path in ("usr/local/bin/python3.13", "usr/local/lib/libpython3.13.so.1.0", "usr/local/LICENSE", "usr/local/lib/python3.13/LICENSE.txt", "usr/lib64/ld-linux-x86-64.so.2"):
            resolved = canonical(path, original)
            if resolved in tree:
                raise ValueError("Duplicate canonical runtime path")
            tree[resolved] = node
    if owned_engine:
        tree.update(owned_bundle(original, owned_engine))
    native_evidence = owned_native_evidence(tree, owned_engine)
    tree.update({"lib": Node("symlink", 0o777, b"usr/lib"), "lib64": Node("symlink", 0o777, b"usr/lib64")})
    if "usr/local/bin/python3.13" not in tree or "usr/local/lib/libpython3.13.so.1.0" not in tree:
        raise ValueError("Pinned Python runtime absent")
    kernel = package(kernel_path, lock["packages"]["kernel"])
    busybox = package(busybox_path, lock["packages"]["busybox"])
    release = lock["kernelRelease"]
    config = kernel["boot/config-" + release].data.decode()
    required = ["CONFIG_RD_GZIP=y", "CONFIG_BLK_DEV_INITRD=y", "CONFIG_DEVTMPFS=y", "CONFIG_HYPERV=m", "CONFIG_HYPERV_STORAGE=m", "CONFIG_VSOCKETS=m", "CONFIG_HYPERV_VSOCKETS=m", "CONFIG_ISO9660_FS=m"]
    if not all(line in config.splitlines() for line in required):
        raise ValueError("Required guest kernel configuration absent")
    tree.update(modules(kernel, release))
    tree["usr/bin/busybox"] = busybox["bin/busybox"]
    tree["sbin/modprobe"] = Node("symlink", 0o777, b"../usr/bin/busybox")
    tree["etc/hostname"] = Node("file", 0o644, b"cline-inert-guest\n")
    tree["etc/hosts"] = Node("file", 0o644, b"127.0.0.1 localhost\n::1 localhost\n")
    for directory in ("dev", "proc", "sys", "run", "tmp", "mnt/cline-boot"):
        tree[directory] = Node("directory", 0o755)
    sources = {"init": HERE / "init", "opt/cline/boot_selftest.py": HERE / "boot_selftest.py", "opt/cline/provision_boot.py": HERE / "provision_boot.py", "opt/cline/guest_probe.py": HERE.parent / "guest_probe.py", "opt/cline/probe_protocol.py": HERE.parent / "probe_protocol.py", "opt/cline/engine_entry.py": HERE / "engine_entry.py"}
    for path, source in sources.items():
        tree[path] = Node("file", 0o755 if path == "init" else 0o644, source.read_bytes())
    if owned_engine:
        fixed = tree["init"].data.decode()
        fixed = fixed.replace("export LD_LIBRARY_PATH=/usr/local/lib", "export LD_LIBRARY_PATH=/opt/cline-engine/syslibs:/usr/local/lib")
        marker = "/usr/local/bin/python3.13 -B -E -s /opt/cline/boot_selftest.py || fail"
        if fixed.count(marker) != 1:
            raise ValueError("Owned init insertion boundary changed")
        fixed = fixed.replace(marker, "$bb mount -t tmpfs -o nosuid,nodev,mode=1777 tmpfs /tmp || fail\n$bb timeout -s KILL 240 /usr/local/bin/python3.13 -B -I /opt/cline/engine_entry.py || fail\n"+marker)
        tree["init"] = Node("file", 0o755, fixed.encode())

    for source, label in [(busybox, "busybox-static"), (kernel, "linux")]:
        for path, node in source.items():
            if path.startswith("usr/share/doc/") and node.kind == "file" and (path.endswith("copyright") or "changelog" in path):
                tree["usr/share/doc/cline-inert-guest/" + label + "-" + Path(path).name] = node
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".cline-inert-image-", dir=output.parent) as staging:
        stage = Path(staging)
        iso_root = stage / "iso"
        boot = iso_root / "boot"
        (boot / "grub").mkdir(parents=True)
        (boot / "vmlinuz").write_bytes(kernel["boot/vmlinuz-" + release].data)
        (boot / "initramfs.gz").write_bytes(cpio(tree))
        grub = 'set timeout=0\nset default=0\nserial --unit=0 --speed=115200\nterminal_output serial\nmenuentry "Cline development inert guest" {\n linux /boot/vmlinuz console=ttyS0,115200 rdinit=/init panic=1 quiet\n initrd /boot/initramfs.gz\n}\n'
        (boot / "grub/grub.cfg").write_text(grub)
        run_tool(["grub-mkrescue", "-o", str(stage / "inert-guest.iso"), str(iso_root), "--modification-date=2024010100000000"], timeout=120, env={**os.environ, "SOURCE_DATE_EPOCH": "1704067200"})
        iso = stage / "inert-guest.iso"
        with iso.open("rb") as stream:
            stream.seek(16 * 2048 + 1)
            if stream.read(5) != b"CD001":
                raise ValueError("Boot ISO descriptor absent")
        manifest = {"schema": 1, "scope": "development-inert-guest", "installable": False, "sourceRevision": revision, "vmIsolation": "not-attested", "engineReadiness": "not-tested", "hypervExchange": "not-tested", "inputs": lock, "rootfsExportSha256": hashlib.sha256(raw).hexdigest(), "generatedInitSha256": hashlib.sha256(tree["init"].data).hexdigest(), "ownedEngine": owned_engine, "ownedEngineBundleSha256": hashlib.sha256(tree["opt/cline-engine/bundle.json"].data).hexdigest() if owned_engine else None, "guestSources": {path: hashlib.sha256(source.read_bytes()).hexdigest() for path, source in sources.items()}, "explicitEntryCount": len(tree), "regularFileCount": sum(n.kind == "file" for n in tree.values()), "artifacts": {"inert-guest.iso": {"sha256": hashlib.sha256(iso.read_bytes()).hexdigest(), "size": iso.stat().st_size}}}
        manifest["ownedNativeBuildSha256"] = hashlib.sha256(native_evidence).hexdigest() if native_evidence is not None else None
        if native_evidence is not None:
            (stage/"native-build.json").write_bytes(native_evidence)
        (stage / "image-manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
        # No image bytes are considered published until the complete build succeeds.
        os.rename(stage, output)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for label in ("rootfs", "kernel", "busybox", "output"):
        parser.add_argument("--" + label, type=Path, required=True)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--owned-engine", choices=["qiling", "unidbg", "rnidbg", "speakeasy"])
    args = parser.parse_args()
    build(args.rootfs, args.kernel, args.busybox, args.output, args.source_revision, args.owned_engine)


if __name__ == "__main__":
    main()
