"""Fixed, static Android artifact investigator. No target execution or key recovery.
Embedded by generate-android-investigation.mjs; stdlib-only discovery and DEX lookup.
"""
import hashlib
import io
import json
import math
import re
import struct
import sys
import zipfile
import zlib

VERSION = "android-static/v1"
MAX_INPUT = 64 * 1024 * 1024
MAX_CHILD = 16 * 1024 * 1024
MAX_WORK = 128 * 1024 * 1024
MAX_RECORDS = 500
MAX_METHODS = 1000
MAX_TOTAL_METHODS = 50000


def stable(*parts):
    return hashlib.sha256(json.dumps(parts, ensure_ascii=True).encode()).hexdigest()[:32]


def u32(data, offset):
    if offset < 0 or offset + 4 > len(data):
        raise ValueError("32-bit read outside artifact")
    return struct.unpack_from("<I", data, offset)[0]


def uleb(data, offset):
    value = 0
    for i in range(5):
        if offset >= len(data):
            raise ValueError("truncated ULEB128")
        byte = data[offset]
        offset += 1
        if i == 4 and byte > 15:
            raise ValueError("ULEB128 overflow")
        value |= (byte & 127) << (7 * i)
        if not byte & 128:
            return value, offset
    raise ValueError("invalid ULEB128")


def dex_string(data, offset):
    units, offset = uleb(data, offset)
    if units > 4096:
        raise ValueError("DEX string exceeds bounded decoder")
    end = data.find(b"\0", offset, min(len(data), offset + 12289))
    if end < 0:
        raise ValueError("unterminated DEX string")
    raw = data[offset:end]
    if any(byte >= 0xf0 for byte in raw):
        raise ValueError("DEX MUTF8 does not use four-byte sequences")
    # DEX uses modified UTF-8; surrogate pairs encode separate UTF-16 units.
    value = raw.replace(b"\xc0\x80", b"\0").decode("utf-8", errors="surrogatepass")
    if len(value.encode("utf-16-le", errors="surrogatepass")) // 2 != units:
        raise ValueError("DEX string length mismatch")
    return value


def dex_metadata(data, limit):
    """Validate header integrity + bounded pool/class-data/code-item ranges.
    This is not full Dalvik instruction, verifier, debug-info or try-handler validation.
    """
    if len(data) < 112 or not re.fullmatch(rb"dex\n0(?:3[5-9]|40)\x00", data[:8]):
        raise ValueError("unsupported DEX magic/version (compact DEX and v041 not supported)")
    if u32(data, 32) != len(data) or u32(data, 36) != 112 or u32(data, 40) != 0x12345678:
        raise ValueError("DEX size/header/endian mismatch")
    if u32(data, 8) != zlib.adler32(data[12:]) & 0xffffffff:
        raise ValueError("DEX Adler32 mismatch")
    if data[12:32] != hashlib.sha1(data[32:]).digest():
        raise ValueError("DEX SHA1 mismatch")
    pools = []
    for header, width in [(56, 4), (64, 4), (72, 12), (80, 8), (88, 8), (96, 32)]:
        count, offset = u32(data, header), u32(data, header + 4)
        if count > 50000 or (count and (offset < 112 or offset % 4 or offset + count * width > len(data))):
            raise ValueError("DEX pool bounds/work limit")
        if not count and offset:
            raise ValueError("empty DEX pool has nonzero offset")
        pools.append((count, offset))
    data_size, data_offset = u32(data, 104), u32(data, 108)
    if data_offset < 112 or data_offset % 4 or data_offset + data_size != len(data):
        raise ValueError("DEX data section bounds")
    map_offset = u32(data, 52)
    if map_offset < data_offset or map_offset % 4:
        raise ValueError("DEX map offset")
    map_count = u32(data, map_offset)
    if not 1 <= map_count <= 256 or map_offset + 4 + 12 * map_count > len(data):
        raise ValueError("DEX map bounds")
    seen = set()
    previous = -1
    for i in range(map_count):
        kind, unused, size, offset = struct.unpack_from("<HHII", data, map_offset + 4 + 12*i)
        if unused or kind in seen or not size or offset <= previous or offset >= len(data):
            raise ValueError("DEX map entries invalid")
        seen.add(kind)
        previous = offset
    strings = []
    string_units = 0
    for i in range(pools[0][0]):
        offset = u32(data, pools[0][1] + i*4)
        if offset < data_offset:
            raise ValueError("DEX string outside data section")
        value = dex_string(data, offset)
        string_units += len(value)
        if string_units > 8 * 1024 * 1024:
            raise ValueError("DEX decoded string work limit")
        strings.append(value)
    types = []
    for i in range(pools[1][0]):
        index = u32(data, pools[1][1] + i*4)
        if index >= len(strings):
            raise ValueError("DEX type index")
        types.append(strings[index])
    protos = []
    parameter_work = 0
    proto_chars = 0
    for i in range(pools[2][0]):
        shorty, ret, params = struct.unpack_from("<III", data, pools[2][1] + 12*i)
        if shorty >= len(strings) or ret >= len(types):
            raise ValueError("DEX proto index")
        arguments = []
        if params:
            if params < data_offset or params % 4:
                raise ValueError("DEX parameter offset")
            n = u32(data, params)
            parameter_work += n
            if parameter_work > 100000:
                raise ValueError("DEX aggregate parameter work limit")
            if n > 4096 or params + 4 + n*2 > len(data):
                raise ValueError("DEX parameter bounds")
            for j in range(n):
                idx = struct.unpack_from("<H", data, params + 4 + 2*j)[0]
                if idx >= len(types):
                    raise ValueError("DEX parameter index")
                arguments.append(types[idx])
        descriptor_chars = 2 + sum(map(len, arguments)) + len(types[ret])
        proto_chars += descriptor_chars
        if descriptor_chars > 8192 or proto_chars > 2 * 1024 * 1024:
            raise ValueError("DEX prototype character budget")
        protos.append("(" + "".join(arguments) + ")" + types[ret])
    methods = []
    for i in range(pools[4][0]):
        cls, proto, name = struct.unpack_from("<HHI", data, pools[4][1] + 8*i)
        if cls >= len(types) or proto >= len(protos) or name >= len(strings):
            raise ValueError("DEX method index")
        methods.append({"methodIndex": i, "classDescriptor": types[cls], "name": strings[name], "descriptor": protos[proto], "defined": False})
    defined = set()
    work = 0
    for i in range(pools[5][0]):
        base = pools[5][1] + i*32
        cls, offset = u32(data, base), u32(data, base+24)
        if cls >= len(types):
            raise ValueError("DEX class index")
        if not offset:
            continue
        if offset < data_offset:
            raise ValueError("DEX class data outside data section")
        counts = []
        for _ in range(4):
            n, offset = uleb(data, offset)
            counts.append(n)
        work += sum(counts)
        if work > 100000:
            raise ValueError("DEX class data work limit")
        for count in counts[:2]:
            idx = 0
            for j in range(count):
                delta, offset = uleb(data, offset)
                _, offset = uleb(data, offset)
                idx += delta
                if idx >= pools[3][0] or (j and not delta):
                    raise ValueError("DEX field delta index")
        for count in counts[2:]:
            idx = 0
            for j in range(count):
                delta, offset = uleb(data, offset)
                flags, offset = uleb(data, offset)
                code, offset = uleb(data, offset)
                idx += delta
                if idx >= len(methods) or idx in defined or (j and not delta) or methods[idx]["classDescriptor"] != types[cls]:
                    raise ValueError("DEX defined method index/class mismatch")
                defined.add(idx)
                method = methods[idx]
                method.update(defined=True, accessFlags=flags, native=bool(flags & 0x100), codeOffset=code)
                if flags & (0x100 | 0x400) and code:
                    raise ValueError("native/abstract DEX method has code")
                if code:
                    if code < data_offset or code % 4 or code + 16 > len(data):
                        raise ValueError("DEX code item header bounds")
                    registers, ins, outs, tries, debug, words = struct.unpack_from("<HHHHII", data, code)
                    end = code + 16 + words*2
                    if ins > registers or end > len(data) or (debug and not data_offset <= debug < len(data)):
                        raise ValueError("DEX code item bounds")
                    if tries and ((end + 3) & ~3) + tries*8 >= len(data):
                        raise ValueError("DEX try table bounds")
                    method.update(registers=registers, instructionOffset=code+16, instructionBytes=words*2,
                                  byteFingerprint=hashlib.sha256(data[code+16:end]).hexdigest())
    # Prioritize native declarations and loader references within bounded output.
    references = [m for m in methods if m["classDescriptor"].startswith(("Ldalvik/system/", "Ljava/lang/reflect/")) or (m["classDescriptor"] in ("Ljava/lang/System;", "Ljava/lang/Runtime;") and m["name"] in ("load", "loadLibrary"))]
    ordered = sorted(methods, key=lambda m: (not m.get("native", False), m["methodIndex"]))
    return {"validation": "integrity-and-bounded-structure", "methodCount": len(methods), "definedMethodCount": len(defined),
            "methods": ordered[:limit], "loaderReferences": [dict(m, referenceOnly=True, executionObserved=False) for m in references[:limit]], "methodsTruncated": len(methods) > limit,
            "loaderReferencesTruncated": len(references) > limit}, methods


def jni_escape(value):
    result = []
    raw = value.encode("utf-16-be", errors="surrogatepass")
    for i in range(0, len(raw), 2):
        unit = int.from_bytes(raw[i:i+2], "big")
        ch = chr(unit)
        result.append(ch if ch.isascii() and ch.isalnum() else {"/": "_", "_": "_1", ";": "_2", "[": "_3"}.get(ch, "_0%04x" % unit))
    return "".join(result)


def investigate(request):
    target = request["target"]
    with open(target, "rb") as handle:
        root = handle.read(MAX_INPUT + 1)
    if len(root) > MAX_INPUT:
        raise ValueError("Android investigation input exceeds 64 MiB")
    limit = max(1, min(int(request.get("limit", 200)), MAX_METHODS))
    options = request.get("options") or {}
    config = options.get("discovery") or {}
    max_depth = min(max(int(config.get("max_depth", 3)), 0), 4)
    artifact_limit = min(max(int(config.get("max_artifacts", 200)), 1), MAX_RECORDS)
    records, warnings, dexes = [], [], []
    relationship_count = 0
    work = [0]
    method_work = [0]
    method_chars = [0]
    truncated = [False]
    def scan(data, label, parent=None, offset=None, depth=0, origin="input"):
        if len(records) >= artifact_limit or work[0] + len(data) > MAX_WORK:
            truncated[0] = True
            return
        work[0] += len(data)
        sha = hashlib.sha256(data).hexdigest()
        identity = stable(parent, label, offset, sha)
        record = {"id": identity, "parentId": parent, "logicalPath": label[:1024], "offsetInParent": offset,
                  "origin": origin, "sha256": sha, "bytes": len(data), "format": "opaque", "validation": "unclassified"}
        records.append(record)
        if data.startswith(b"dex\n") or data.startswith(b"cdex"):
            record["format"] = "dex"
            try:
                if method_work[0] + u32(data, 88) > MAX_TOTAL_METHODS:
                    truncated[0] = True
                    raise ValueError("DEX investigation aggregate method budget")
                meta, methods = dex_metadata(data, limit)
                chars = sum(len(m["classDescriptor"]) + len(m["name"]) + len(m["descriptor"]) for m in methods)
                if method_chars[0] + chars > 16 * 1024 * 1024:
                    truncated[0] = True
                    raise ValueError("DEX investigation aggregate method text budget")
                method_work[0] += len(methods)
                method_chars[0] += chars
                record.update(validation=meta.pop("validation"), dex=meta)
                dexes.append((record, methods))
            except (ValueError, struct.error, UnicodeError) as exc:
                record.update(validation="candidate-rejected-or-unsupported", reason=str(exc))
        elif data.startswith(b"\x7fELF"):
            record["format"] = "elf"
            record["validation"] = "signature-only-candidate"
            record["reason"] = "Use native_inventory for LIEF structural evidence; no ELF execution"
        elif data.startswith(b"PK\x03\x04") or data.startswith(b"PK\x05\x06"):
            record["format"] = "zip"
            record["validation"] = "container-candidate"
            if depth >= max_depth:
                truncated[0] = True
                return
            try:
                with zipfile.ZipFile(io.BytesIO(data)) as archive:
                    entries = archive.infolist()
                    if len(entries) > 10000:
                        raise ValueError("ZIP entry limit")
                    names = set()
                    for entry in entries:
                        name = entry.filename
                        if len(name) > 1024 or name in names or "\\" in name or name.startswith("/") or ":" in name or any(p == ".." for p in name.split("/")) or (entry.external_attr >> 16) & 0o170000 == 0o120000 or entry.flag_bits & 1:
                            raise ValueError("unsafe/duplicate/encrypted ZIP member")
                        names.add(name)
                    record["validation"] = "central-directory-checked"
                    record["entryCount"] = len(entries)
                    for entry in entries:
                        if entry.is_dir():
                            continue
                        if len(records) >= artifact_limit or entry.file_size > MAX_CHILD or entry.file_size > max(1, entry.compress_size)*100 or work[0] + entry.file_size > MAX_WORK:
                            truncated[0] = True
                            continue
                        with archive.open(entry) as member:
                            child = member.read(MAX_CHILD+1)
                        if len(child) != entry.file_size or len(child) > MAX_CHILD:
                            raise ValueError("ZIP expanded size mismatch")
                        scan(child, entry.filename, identity, None, depth+1, "zip-member")
            except (ValueError, zipfile.BadZipFile, RuntimeError, OSError, EOFError, zlib.error) as exc:
                record.update(validation="container-partial-or-rejected", reason=str(exc))
                warnings.append("ZIP traversal incomplete: " + str(exc))
        elif data.startswith(b"\x1f\x8b") or (len(data) >= 2 and data[0] & 15 == 8 and int.from_bytes(data[:2], "big") % 31 == 0):
            record["format"] = "gzip" if data.startswith(b"\x1f\x8b") else "zlib"
            if depth >= max_depth:
                truncated[0] = True
                return
            try:
                decoder = zlib.decompressobj(31 if record["format"] == "gzip" else 15)
                child = decoder.decompress(data, MAX_CHILD+1)
                if len(child) > MAX_CHILD or len(child) > max(1,len(data))*100 or not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
                    raise ValueError("compression expansion/trailing-data limit")
                record["validation"] = "bounded-decompression"
                scan(child, "decompressed", identity, None, depth+1, record["format"] + "-expansion")
            except (zlib.error, ValueError) as exc:
                record.update(validation="compression-rejected", reason=str(exc))
        if record["format"] == "opaque":
            sample = data[:1048576]
            counts = [0]*256
            for byte in sample:
                counts[byte] += 1
            record["sampleEntropy"] = -sum((c/len(sample))*math.log2(c/len(sample)) for c in counts if c) if sample else 0
            record["entropyInterpretation"] = "Not evidence of encryption; compressed/random data can also have high entropy"
        # Carve standard DEX candidates from otherwise opaque/native payloads, bounded.
        if record["format"] in ("opaque", "elf") and depth < max_depth:
            hits = 0
            for match in re.finditer(rb"dex\n0(?:3[5-9]|40)\x00", data):
                hits += 1
                if hits > 64 or len(records) >= artifact_limit:
                    truncated[0] = True
                    break
                pos = match.start()
                if pos + 112 > len(data):
                    continue
                size = u32(data, pos+32)
                if 112 <= size <= MAX_CHILD and pos + size <= len(data):
                    scan(data[pos:pos+size], "embedded-dex@%x" % pos, identity, pos, depth+1, "carved")
                else:
                    warnings.append("DEX signature at %d has invalid/truncated declared size" % pos)
        elif record["format"] in ("opaque", "elf") and depth >= max_depth:
            truncated[0] = True
    scan(root, "input")
    selected = []
    relationships = []
    selector = options.get("method")
    if request["action"] == "android_method" and not selector:
        raise ValueError("android_method requires exact class_descriptor, name and descriptor")
    for artifact, methods in dexes:
        for method in methods:
            method["id"] = stable(artifact["id"], method["methodIndex"])
            method["artifactId"] = artifact["id"]
            if selector and (method["classDescriptor"],method["name"],method["descriptor"]) == (selector["class_descriptor"],selector["name"],selector["descriptor"]):
                selected.append(method)
            if method.get("native"):
                relationship_count += 1
            if method.get("native") and len(relationships) < limit:
                short = "Java_" + jni_escape(method["classDescriptor"][1:-1]) + "_" + jni_escape(method["name"])
                parameters = method["descriptor"].split(")",1)[0][1:]
                relationships.append({"id": stable(method["id"], "jni-name"), "methodId": method["id"], "artifactId": artifact["id"], "kind": "jni-name-candidate", "shortName": short, "longName": short + "__" + jni_escape(parameters), "confidence": "derived-name-only", "verifiedBinding": False})
    for artifact, _ in dexes:
        for method in artifact["dex"]["methods"] + artifact["dex"]["loaderReferences"]:
            method["id"] = stable(artifact["id"],method["methodIndex"])
            method["artifactId"] = artifact["id"]
    evidence = {"schemaVersion": 1, "artifacts": records, "relationships": relationships,
                "relationshipCount": relationship_count, "relationshipsTruncated": relationship_count > limit,
                "coverage": {"processedBytes": work[0], "parsedMethodCount": method_work[0], "maxParsedMethods": MAX_TOTAL_METHODS, "maxDepth": max_depth, "artifactLimit": artifact_limit, "truncated": truncated[0]}, "warnings": warnings[:64]}
    limitations = ["Static input processing only; no target execution, arbitrary key recovery or full devirtualization.",
                   "DEX validation covers integrity and bounded structures, not full bytecode verification. Modified/unsupported DEX remains a candidate.",
                   "Loader references are pool references, not proven executed calls. JNI names are candidates, not observed RegisterNatives bindings.",
                   "ELF signatures are candidates; use native_inventory for structural validation. Nested APK/ZIP and compression inspection is bounded."]
    status = "partial" if truncated[0] or warnings or any("rejected" in r["validation"] or "candidate" in r["validation"] for r in records) else "completed"
    if request["action"] == "android_method":
        evidence["selectedMethods"] = selected[:limit]
        evidence["selectedMethodCount"] = len(selected)
        evidence["selectedMethodsTruncated"] = len(selected) > limit
        evidence["selectionStatus"] = "found" if selected else "not-found-in-covered-artifacts"
        evidence["ambiguousAcrossArtifacts"] = len(selected) > 1
        status = "partial" if not selected or truncated[0] or len(selected) > limit else status
    if relationship_count > limit or any(r.get("dex",{}).get("methodsTruncated") or r.get("dex",{}).get("loaderReferencesTruncated") for r in records):
        status = "partial"
        limitations.append("Method/reference listings truncated; exact selection searches parsed method pools within stated limits.")
    return {"protocol": "cline-advanced-analysis/v1", "status": status, "engine": "android-static", "engineVersion": VERSION,
            "input": {"sha256": hashlib.sha256(root).hexdigest(), "bytes": len(root), "format": records[0]["format"]}, "evidence": evidence, "limitations": limitations}


def main():
    try:
        request = json.loads(sys.argv[1])
        if request["action"] not in ("artifact_discovery", "android_relationships", "android_method"):
            raise ValueError("Unsupported Android investigation action")
        result = investigate(request)
        output = json.dumps(result, ensure_ascii=True, separators=(",", ":"))
        if len(output.encode()) > 900000:
            raise ValueError("Android evidence exceeds bounded output; reduce max_artifacts/limit")
        print(output)
    except Exception as exc:
        print(json.dumps({"protocol":"cline-advanced-analysis/v1", "status":"failed", "engine":"android-static", "engineVersion":VERSION, "evidence":{"reason":str(exc)}, "limitations":["No successful analysis implied by failure"]}))


if __name__ == "__main__":
    main()
