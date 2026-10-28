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


def build(rootfs, kernel_path, busybox_path, output, revision):
    if not re.fullmatch("[0-9a-f]{40}", revision) or output.exists() or output.is_symlink():
        raise ValueError("New output and exact source revision required")
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
    sources = {"init": HERE / "init", "opt/cline/boot_selftest.py": HERE / "boot_selftest.py", "opt/cline/provision_boot.py": HERE / "provision_boot.py", "opt/cline/guest_probe.py": HERE.parent / "guest_probe.py", "opt/cline/probe_protocol.py": HERE.parent / "probe_protocol.py"}
    for path, source in sources.items():
        tree[path] = Node("file", 0o755 if path == "init" else 0o644, source.read_bytes())
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
        manifest = {"schema": 1, "scope": "development-inert-guest", "installable": False, "sourceRevision": revision, "vmIsolation": "not-attested", "engineReadiness": "not-tested", "hypervExchange": "not-tested", "inputs": lock, "rootfsExportSha256": hashlib.sha256(raw).hexdigest(), "guestSources": {path: hashlib.sha256(source.read_bytes()).hexdigest() for path, source in sources.items()}, "fileCount": len(tree), "artifacts": {"inert-guest.iso": {"sha256": hashlib.sha256(iso.read_bytes()).hexdigest(), "size": iso.stat().st_size}}}
        (stage / "image-manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
        # No image bytes are considered published until the complete build succeeds.
        os.rename(stage, output)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for label in ("rootfs", "kernel", "busybox", "output"):
        parser.add_argument("--" + label, type=Path, required=True)
    parser.add_argument("--source-revision", required=True)
    args = parser.parse_args()
    build(args.rootfs, args.kernel, args.busybox, args.output, args.source_revision)


if __name__ == "__main__":
    main()
