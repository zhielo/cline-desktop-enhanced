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
import xml.etree.ElementTree as ET

VERSION = "android-static/v7"
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


def dex_metadata(data, limit, include_classes=False):
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
    classes = []
    defined = set()
    work = 0
    for i in range(pools[5][0]):
        base = pools[5][1] + i*32
        cls, offset = u32(data, base), u32(data, base+24)
        if cls >= len(types):
            raise ValueError("DEX class index")
        if include_classes:
            super_index = u32(data, base+8)
            if super_index != 0xffffffff and super_index >= len(types):
                raise ValueError("DEX superclass index")
            classes.append({"descriptor":types[cls], "superclass":None if super_index == 0xffffffff else types[super_index], "classIndex":i})
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
            "loaderReferencesTruncated": len(references) > limit, **({"classes":classes} if include_classes else {})}, methods


def jni_escape(value):
    result = []
    raw = value.encode("utf-16-be", errors="surrogatepass")
    for i in range(0, len(raw), 2):
        unit = int.from_bytes(raw[i:i+2], "big")
        ch = chr(unit)
        result.append(ch if ch.isascii() and ch.isalnum() else {"/": "_", "_": "_1", ";": "_2", "[": "_3"}.get(ch, "_0%04x" % unit))
    return "".join(result)


def native_metadata(data, artifact_id, limit):
    import importlib.metadata
    import tempfile
    from pathlib import Path
    import lief
    if not data.startswith(b"\x7fELF") or len(data)<16 or data[4] not in (1,2) or len(data)<(52 if data[4]==1 else 64) or data[5] != 1:
        raise ValueError("Native analysis supports bounded little-endian ELF only")
    with tempfile.TemporaryDirectory(prefix="cline-static-elf-") as directory:
        file = Path(directory) / "input.so"
        file.write_bytes(data)
        file.chmod(0o600)
        binary = lief.ELF.parse(str(file))
        if binary is None:
            raise ValueError("LIEF did not parse ELF")
        machine = int.from_bytes(data[18:20], "little")
        architecture = {183:"arm64",40:"arm",62:"x86_64",3:"x86"}.get(machine,"unsupported")
        segments = []
        for segment in binary.segments:
            if str(segment.type).split(".")[-1] != "LOAD":
                continue
            offset, size, address = int(segment.file_offset), int(segment.physical_size), int(segment.virtual_address)
            if offset < 0 or size < 0 or offset + size > len(data):
                raise ValueError("ELF load segment file bounds invalid")
            segments.append({"fileOffset":offset,"fileBytes":size,"addressHex":hex(address),"executable":bool(int(segment.flags)&1)})
        functions, exports, seen = [], [], set()
        for symbol,source in [(s,"dynamic") for s in binary.dynamic_symbols] + [(s,"symtab") for s in binary.symtab_symbols]:
            if str(symbol.type).split(".")[-1] != "FUNC" or int(symbol.shndx) == 0 or not symbol.name:
                continue
            address, size, name = int(symbol.value), int(symbol.size), symbol.name
            if len(name) > 4096:
                raise ValueError("ELF symbol name limit")
            key=(name,address,size)
            if key in seen:
                continue
            seen.add(key)
            if len(seen) > 50000:
                raise ValueError("ELF function work budget")
            normalized = address & ~1 if architecture == "arm" else address
            mappings=[s for s in segments if int(s["addressHex"],16) <= normalized < int(s["addressHex"],16)+s["fileBytes"]]
            record={"id":stable(artifact_id,name,address,size),"artifactId":artifact_id,"name":name,"addressHex":hex(address),"size":size,"architecture":"thumb" if architecture=="arm" and address & 1 else architecture,"rangeValidation":"unmapped-or-ambiguous"}
            if len(mappings)==1:
                segment=mappings[0];offset=segment["fileOffset"]+normalized-int(segment["addressHex"],16)
                record.update(fileOffset=offset,segmentFileEnd=segment["fileOffset"]+segment["fileBytes"],rangeValidation="mapped-file-backed-range")
                if not segment["executable"]:record["rangeValidation"]="non-executable-file-backed-symbol"
                if size and offset+size > record["segmentFileEnd"]:
                    record["rangeValidation"]="symbol-range-exceeds-segment"
            functions.append(record)
            if source=="dynamic" and name.startswith("Java_") and str(symbol.binding).split(".")[-1] in ("GLOBAL","WEAK") and str(symbol.visibility).split(".")[-1] in ("DEFAULT","PROTECTED"):
                exports.append(dict(record,exportEvidence="defined-global-or-weak-ELF-symbol"))
        return {"engine":"lief","engineVersion":importlib.metadata.version("lief"),"architecture":architecture,"image":{"preferredBaseHex":hex(int(binary.imagebase)),"addressSpace":"elf-link-time-virtual","runtimeBase":"unknown"},"segments":segments[:limit],"segmentsTruncated":len(segments)>limit,"functions":functions[:limit],"functionCount":len(functions),"functionsTruncated":len(functions)>limit,"jniExports":exports[:limit],"jniExportsTruncated":len(exports)>limit},functions


def disassemble_selected(data, method, maximum, segments=None):
    import importlib.metadata
    import capstone
    if method["rangeValidation"] != "mapped-file-backed-range" or not method["size"]:
        return {"status":"blocked","reason":"No unique file-backed nonzero symbol range; no function extent is inferred"}
    architectures={"arm64":(capstone.CS_ARCH_ARM64,capstone.CS_MODE_ARM),"arm":(capstone.CS_ARCH_ARM,capstone.CS_MODE_ARM),"thumb":(capstone.CS_ARCH_ARM,capstone.CS_MODE_THUMB),"x86":(capstone.CS_ARCH_X86,capstone.CS_MODE_32),"x86_64":(capstone.CS_ARCH_X86,capstone.CS_MODE_64)}
    if method["architecture"] not in architectures:
        return {"status":"blocked","reason":"Unsupported disassembly architecture"}
    count=min(method["size"],maximum,65536)
    offset=method["fileOffset"]
    engine=capstone.Cs(*architectures[method["architecture"]]);engine.detail=True
    address=int(method["addressHex"],16)
    if method["architecture"]=="thumb":address &= ~1
    instructions=[];decoded=0;references=[];strings=[];callees=[];register_values={};indirect_calls=[]
    for instruction in engine.disasm(data[offset:offset+count],address):
        if len(instructions)>=1000:break
        calls=[]
        if instruction.group(capstone.CS_GRP_CALL):
            for operand in instruction.operands:
                if operand.type==capstone.CS_OP_IMM:calls.append(hex(operand.imm))
        callees.extend({"fromAddressHex":hex(instruction.address),"targetAddressHex":call,"confidence":"decoded-direct-call-candidate"} for call in calls)
        if method["architecture"]=="x86_64":
            from capstone import x86_const as x86
            if instruction.group(capstone.CS_GRP_CALL) and not calls:
                target=None;operand=instruction.operands[0] if instruction.operands else None
                if operand is not None and operand.type==capstone.CS_OP_REG:target=register_values.get(operand.reg)
                record={"fromAddressHex":hex(instruction.address),"resolution":"constant-register-static-candidate" if target is not None else "unknown-register-or-memory-target"}
                if target is not None and 0<target<2**64:
                    record["targetAddressHex"]=hex(target);callees.append(dict(record,confidence="bounded-straight-line-indirect-call-candidate-not-runtime"))
                else:record["resolution"]="unknown-register-or-memory-target"
                if len(indirect_calls)<128:indirect_calls.append(record)
            _,written=instruction.regs_access()
            candidate=None;destination=None
            if instruction.mnemonic in ("mov","movabs") and len(instruction.operands)==2:
                left,right=instruction.operands
                if left.type==capstone.CS_OP_REG and left.size==8 and right.type==capstone.CS_OP_IMM:destination=left.reg;candidate=right.imm%(2**64)
                elif left.type==capstone.CS_OP_REG and left.size==8 and right.type==capstone.CS_OP_REG:destination=left.reg;candidate=register_values.get(right.reg)
            elif instruction.mnemonic=="lea" and len(instruction.operands)==2:
                left,right=instruction.operands
                if left.type==capstone.CS_OP_REG and left.size==8 and right.type==capstone.CS_OP_MEM and right.mem.base==x86.X86_REG_RIP and right.mem.index==0:destination=left.reg;candidate=instruction.address+instruction.size+right.mem.disp
            # Subregister writes invalidate full-width aliases, not just the recorded register ID.
            alias_groups=[(x86.X86_REG_RAX,x86.X86_REG_EAX,x86.X86_REG_AX,x86.X86_REG_AL,x86.X86_REG_AH),(x86.X86_REG_RBX,x86.X86_REG_EBX,x86.X86_REG_BX,x86.X86_REG_BL,x86.X86_REG_BH),(x86.X86_REG_RCX,x86.X86_REG_ECX,x86.X86_REG_CX,x86.X86_REG_CL,x86.X86_REG_CH),(x86.X86_REG_RDX,x86.X86_REG_EDX,x86.X86_REG_DX,x86.X86_REG_DL,x86.X86_REG_DH)]
            # For other aliases conservatively drop all values on any unsupported write.
            for register in written:
                group=next((g for g in alias_groups if register in g),None)
                if group is None:register_values.clear()
                else:
                    for alias in group:register_values.pop(alias,None)
            if destination is not None and candidate is not None:register_values[destination]=candidate
            if instruction.group(capstone.CS_GRP_JUMP) or instruction.group(capstone.CS_GRP_CALL) or instruction.group(capstone.CS_GRP_RET):register_values.clear()
        if method["architecture"]!="x86_64" and instruction.group(capstone.CS_GRP_CALL) and not calls:
            if len(indirect_calls)<128:indirect_calls.append({"fromAddressHex":hex(instruction.address),"resolution":"unknown-register-or-memory-target"})
        if method["architecture"]=="x86_64" and segments is not None:
            for operand in instruction.operands:
                if operand.type != capstone.CS_OP_MEM or operand.mem.base != capstone.x86_const.X86_REG_RIP:continue
                target=instruction.address+instruction.size+operand.mem.disp
                if target<0 or len(references)>=128:continue
                references.append({"fromAddressHex":hex(instruction.address),"targetAddressHex":hex(target),"confidence":"decoded-rip-relative-address-candidate"})
                mappings=[seg for seg in segments if int(seg["addressHex"],16)<=target<int(seg["addressHex"],16)+seg["fileBytes"]]
                if len(mappings)!=1 or len(strings)>=64:continue
                seg=mappings[0];at=seg["fileOffset"]+target-int(seg["addressHex"],16)
                end=min(at+129,seg["fileOffset"]+seg["fileBytes"],len(data))
                if at<0 or at>=end:continue
                preview=data[at:end];terminator=preview.find(b"\0")
                if not 3<=terminator<=128 or any(c<32 or c>126 for c in preview[:terminator]):continue
                value=preview[:terminator]
                strings.append({"fromAddressHex":hex(instruction.address),"addressHex":hex(target),"fileOffset":at,"value":value.decode("ascii"),"sha256":hashlib.sha256(value).hexdigest(),"confidence":"file-backed-ascii-reference-candidate-not-runtime-read"})
        instructions.append({"addressHex":hex(instruction.address),"bytes":instruction.bytes.hex(),"mnemonic":instruction.mnemonic,"operands":instruction.op_str,"directCallCandidates":calls})
        decoded+=instruction.size
    return {"engine":"capstone","engineVersion":importlib.metadata.version("capstone"),"architecture":method["architecture"],"references":references,"strings":strings,"callees":callees[:128],"indirectCalls":indirect_calls,"relationsTruncated":len(callees)>128 or len(indirect_calls)>=128 or len(references)>=128 or len(strings)>=64,"status":"completed" if decoded==method["size"] else "partial","instructions":instructions,"requestedBytes":count,"decodedBytes":decoded,"byteFingerprint":hashlib.sha256(data[offset:offset+count]).hexdigest(),"coverage":"bounded-linear-disassembly-not-a-CFG-or-runtime-trace"}


def selected_dex_code(data, selector, limit):
    import importlib.metadata
    from androguard.core.dex import DEX
    from loguru import logger
    logger.disable("androguard")
    dex=DEX(data)
    results=[]
    for cls in dex.get_classes():
        if cls.get_name()!=selector["class_descriptor"]:continue
        for method in cls.get_methods():
            if method.get_name()!=selector["name"] or method.get_descriptor().replace(" ","")!=selector["descriptor"]:continue
            code=method.get_code()
            instructions=[];position=0;truncated=False
            if code:
                for ins in code.get_bc().get_instructions():
                    if len(instructions)>=limit:truncated=True;break
                    instructions.append({"bytecodeOffset":position,"name":ins.get_name(),"operands":ins.get_output()[:4096]})
                    position+=ins.get_length()
            results.append({"classDescriptor":cls.get_name(),"name":method.get_name(),"descriptor":method.get_descriptor().replace(" ",""),"instructions":instructions,"instructionsTruncated":truncated,"hasCode":code is not None})
    return {"engine":"androguard","engineVersion":importlib.metadata.version("androguard"),"methods":results,"coverage":"selected-defined-method-bytecode-not-recovered-source-or-runtime-execution"}


def native_call_budget(options):
    defaults={"max_depth":2,"max_functions":16,"max_edges":128,"max_total_bytes":32768}
    caps={"max_depth":4,"max_functions":32,"max_edges":256,"max_total_bytes":65536}
    if not isinstance(options,dict) or set(options)-set(defaults):raise ValueError("Invalid native_calls budget fields")
    result=dict(defaults)
    for key,value in options.items():
        if type(value) is not int or not (0 if key=="max_depth" else 1)<=value<=caps[key]:raise ValueError("Invalid native_calls budget")
        result[key]=value
    return result


def native_call_traversal(data, root, root_body, functions, meta, budget, per_function):
    # One immutable byte buffer and one LIEF parse. Exact entries only; never guess extents.
    entries={}
    def entry(method):
        value=int(method["addressHex"],16)
        return value & ~1 if method["architecture"]=="thumb" else value
    for method in functions:entries.setdefault(entry(method),[]).append(method)
    queue=[(root,0,root_body)];scheduled={root["id"]};nodes=[];edges=[];reasons=set();charged=0
    while queue:
        method,depth,body=queue.pop(0)
        if body is None:
            maximum=min(per_function,budget["max_total_bytes"]-charged)
            if maximum<=0:
                body={"status":"blocked","reason":"Total instruction-byte budget exhausted"};reasons.add("max_total_bytes")
            else:
                try:body=disassemble_selected(data,method,maximum,None if meta["segmentsTruncated"] else meta["segments"])
                except ImportError:body={"status":"blocked","reason":"Capstone is not installed"}
        charged+=body.get("requestedBytes",0)
        node={key:method[key] for key in ("id","name","addressHex","architecture","size","rangeValidation")}
        node.update(depth=depth,status=body["status"],requestedBytes=body.get("requestedBytes",0),decodedBytes=body.get("decodedBytes",0),byteFingerprint=body.get("byteFingerprint"),reason=body.get("reason"))
        nodes.append(node)
        if body["status"]!="completed":reasons.add("partial-or-blocked-function")
        if body.get("relationsTruncated"):reasons.add("function-relations-truncated")
        calls=[dict(call,kind="direct") for call in body.get("callees",[]) if call.get("confidence")=="decoded-direct-call-candidate"]
        calls.extend(dict(call,kind="indirect") for call in body.get("indirectCalls",[]))
        for call in calls:
            if len(edges)>=budget["max_edges"]:
                reasons.add("max_edges");break
            edge={"fromNodeId":method["id"],"fromAddressHex":call["fromAddressHex"],"kind":call["kind"],"confidence":"static-candidate-not-observed-execution"}
            if "targetAddressHex" in call:edge["targetAddressHex"]=call["targetAddressHex"]
            edges.append(edge)
            if call["kind"]=="indirect":
                edge["resolution"]="indirect-not-followed";edge["targetEvidence"]=call.get("resolution","unknown");continue
            target=int(call["targetAddressHex"],16)
            # ARM BLX can change instruction set. The declared symbol determines decoding mode.
            candidates=entries.get(target,[])
            if method["architecture"] in ("arm","thumb") and not candidates:candidates=entries.get(target & ~1,[])
            if len(candidates)!=1:
                edge["resolution"]="ambiguous-entry" if candidates else "no-exact-symbol-entry";edge["matchCount"]=len(candidates);continue
            candidate=candidates[0];edge["toNodeId"]=candidate["id"]
            if candidate["id"] in scheduled:edge["resolution"]="already-scheduled-or-visited";continue
            if depth>=budget["max_depth"]:edge["resolution"]="depth-limit";reasons.add("max_depth");continue
            if len(scheduled)>=budget["max_functions"]:edge["resolution"]="function-limit";reasons.add("max_functions");continue
            if charged>=budget["max_total_bytes"]:edge["resolution"]="byte-limit";reasons.add("max_total_bytes");continue
            edge["resolution"]="exact-entry-scheduled";scheduled.add(candidate["id"]);queue.append((candidate,depth+1,None))
    node_status={node["id"]:node["status"] for node in nodes}
    for edge in edges:
        if edge.get("toNodeId") in node_status:edge["targetStatus"]=node_status[edge["toNodeId"]]
    return {"protocol":"cline-native-call-graph/v1","status":"partial","observedExecution":False,"rootNodeId":root["id"],"budgets":dict(budget,max_function_bytes=per_function),"usage":{"functions":len(nodes),"edges":len(edges),"requestedBytes":charged},"nodes":nodes,"edges":edges,"coverage":{"limitsReached":sorted(reasons),"metadataRowsTruncated":meta["functionsTruncated"],"symbolIndexCount":len(functions)},"limitations":["Bounded breadth-first ELF symbol-entry traversal of linear decoded direct-call candidates only; not a complete CFG, caller graph, tail-call analysis or proof of reachable/runtime behavior.","Indirect calls (including constant-register candidates), missing symbols, aliases and ambiguous mappings are not followed. PLT/imports and stripped code are not resolved. Per-function instruction/relationship and global budgets can leave paths unknown.","Every address is ELF link-time virtual, not an observed load address. No target code, debugger, shell or device is executed."]}


def native_selection(request):
    with open(request["target"],"rb") as file:data=file.read(MAX_INPUT+1)
    if len(data)>MAX_INPUT:raise ValueError("Native input limit")
    selector=(request.get("options") or {}).get("function")
    if not selector or (bool(selector.get("symbol"))==bool(selector.get("address"))):
        raise ValueError("native_function requires exactly one exact symbol or entry address")
    artifact=stable(None,"input",None,hashlib.sha256(data).hexdigest())
    meta,functions=native_metadata(data,artifact,max(1,min(request.get("limit",200),1000)))
    address=int(str(selector["address"]),0) if selector.get("address") else None
    matches=[m for m in functions if m["name"]==selector.get("symbol") or (address is not None and int(m["addressHex"],16)==address)]
    traversal_options=(request.get("options") or {}).get("native_calls")
    budget=native_call_budget(traversal_options) if traversal_options is not None else None
    maximum=selector.get("max_bytes",4096)
    if type(maximum) is not int or not 1<=maximum<=65536:raise ValueError("Invalid native function byte budget")
    selections=[]
    selected_matches=matches[:20] if budget is None else (matches if len(matches)==1 else [])
    for method in selected_matches:
        try:body=disassemble_selected(data,method,min(maximum,budget["max_total_bytes"]) if budget else maximum,None if meta["segmentsTruncated"] else meta["segments"])
        except ImportError:body={"status":"blocked","reason":"Capstone is not installed"}
        selections.append(dict(method,image=meta["image"],disassembly=body,references=body.get("references","unknown"),strings=body.get("strings","unknown"),callees=body.get("callees","unknown"),indirectCalls=body.get("indirectCalls","unknown")))
    graph=None
    if budget:
        if len(matches)==1:graph=native_call_traversal(data,matches[0],selections[0]["disassembly"],functions,meta,budget,maximum)
        else:graph={"protocol":"cline-native-call-graph/v1","status":"partial","observedExecution":False,"nodes":[],"edges":[],"reason":"Root selector must match exactly one symbol; no traversal performed","matchCount":len(matches),"budgets":budget}
    return {"protocol":"cline-advanced-analysis/v1","status":"completed" if not budget and len(matches)==1 and selections[0]["disassembly"]["status"]=="completed" and not meta["functionsTruncated"] else "partial","engine":"android-static","engineVersion":VERSION,"input":{"sha256":hashlib.sha256(data).hexdigest(),"bytes":len(data),"format":"elf"},"evidence":{"schemaVersion":1,"artifacts":[{"id":artifact,"sha256":hashlib.sha256(data).hexdigest(),"format":"elf","validation":"LIEF-parsed-bounded-file-mappings","native":meta}],**({"callGraph":graph} if graph is not None else {}),"relationships":[],"selectedFunctions":selections,"matchCount":len(matches),"ambiguous":len(matches)>1,"coverage":{"truncated":len(matches)>20 or meta["functionsTruncated"]}},"limitations":["Static bounded ELF symbol analysis only; not function discovery in stripped/virtualized code, runtime execution, JNI registration proof or semantic equivalence.","Capstone output is linear range disassembly, not a complete CFG; direct calls and x86_64 RIP-relative ASCII references are static candidates, not runtime accesses. Preferred ELF base is link-time metadata, not ASLR/load-base proof. Addresses are preserved as hexadecimal strings."]}


def analysis_readiness():
    import base64
    import importlib.metadata
    checks=[]
    dex=base64.b64decode('ZGV4CjAzNQBQQLuGcWAtJD6Si/Jnkkf5696c8X/9f57sAQAAcAAAAHhWNBIAAAAAAAAAAGQBAAAIAAAAcAAAAAQAAACQAAAAAgAAAKAAAAAAAAAAAAAAAAIAAAC4AAAAAQAAAMgAAAAEAQAA6AAAAOgAAADzAAAABwEAAAoBAAAeAQAAKwEAADgBAAA7AQAAAAAAAAEAAAACAAAAAwAAAAYAAAACAAAAAAAAAAcAAAACAAAAQAEAAAAAAAAEAAAAAQABAAUAAAAAAAAAAQAAAP////8AAAAA/////wAAAABaAQAAAAAAAAlMRml4dHVyZTsAEkxqYXZhL2xhbmcvU3lzdGVtOwABVgASTGphdmEvbGFuZy9TdHJpbmc7AAtuYXRpdmVfd29yawALbG9hZExpYnJhcnkAAVYAAlZMAAABAAAAAwAAAAEAAAAAAAAAAAAAAAEAAAAOAAAAAQAAAcgCAAALAAAAAAAAAAEAAAAAAAAAAQAAAAgAAABwAAAAAgAAAAQAAACQAAAAAwAAAAIAAACgAAAABQAAAAIAAAC4AAAABgAAAAEAAADIAAAAAiAAAAgAAADoAAAAARAAAAEAAABAAQAAASAAAAEAAABIAQAAACAAAAEAAABaAQAAABAAAAEAAABkAQAA')
    elf=base64.b64decode('f0VMRgIBAQAAAAAAAAAAAAMAPgABAAAAAAAAAAAAAABAAAAAAAAAALgBAAAAAAAAAAAAAEAAOAACAEAABwAGAAEAAAAFAAAAAAAAAAAAAAAAAEAAAAAAAAAAQAAAAAAAeAMAAAAAAAB4AwAAAAAAAAAQAAAAAAAAAgAAAAQAAAAoAQAAAAAAACgBQAAAAAAAKAFAAAAAAABgAAAAAAAAAGAAAAAAAAAACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAkMMASmF2YV9GaXh0dXJlX25hdGl2ZV8xd29yawAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAEgABAMAAQAAAAAAAAgAAAAAAAAABAAAAAgAAAAEAAAAAAAAAAAAAAAAAAAAFAAAAAAAAAMIAQAAAAAAACgAAAAAAAAAbAAAAAAAAAAYAAAAAAAAA4ABAAAAAAAALAAAAAAAAABgAAAAAAAAABAAAAAAAAAAQAUAAAAAAAAAAAAAAAAAAAAAAAAAAAAAALnRleHQALmR5bnN0cgAuZHluc3ltAC5oYXNoAC5keW5hbWljAC5zaHN0cnRhYgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAEAAAAGAAAAAAAAAMAAQAAAAAAAwAAAAAAAAAACAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAcAAAADAAAAAgAAAAAAAADCAEAAAAAAAMIAAAAAAAAAGwAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAPAAAACwAAAAIAAAAAAAAA4ABAAAAAAADgAAAAAAAAADAAAAAAAAAAAgAAAAAAAAAIAAAAAAAAABgAAAAAAAAAFwAAAAUAAAACAAAAAAAAABABQAAAAAAAEAEAAAAAAAAUAAAAAAAAAAMAAAAAAAAABAAAAAAAAAAEAAAAAAAAAB0AAAAGAAAAAwAAAAAAAAAoAUAAAAAAACgBAAAAAAAAYAAAAAAAAAACAAAAAAAAAAgAAAAAAAAAEAAAAAAAAAAmAAAAAwAAAAAAAAAAAAAAAAAAAAAAAACIAQAAAAAAADAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAA')
    for name,run in [
        ("stdlib-dex-validator",lambda:dex_metadata(dex,20)),
        ("lief",lambda:native_metadata(elf,"owned-self-test",20)),
        ("capstone",lambda:disassemble_selected(elf,native_metadata(elf,"owned-self-test",20)[1][0],32)),
        ("androguard",lambda:selected_dex_code(dex,{"class_descriptor":"LFixture;","name":"native_work","descriptor":"()V"},20)),
    ]:
        try:
            result=run()
            if name=="capstone" and result["decodedBytes"]!=2:raise ValueError("Owned instruction self-test mismatch")
            if name=="androguard" and not result["methods"][0]["instructions"]:raise ValueError("Owned DEX code self-test mismatch")
            checks.append({"engine":name,"status":"completed","executionVerified":True,"scope":"owned-static-fixture-only","version":importlib.metadata.version(name) if name!="stdlib-dex-validator" else VERSION})
        except ImportError:checks.append({"engine":name,"status":"blocked","executionVerified":False,"reason":"Required static engine missing"})
        except Exception as exc:checks.append({"engine":name,"status":"failed","executionVerified":False,"reason":str(exc)[:500]})
    return {"protocol":"cline-advanced-analysis/v1","status":"completed" if all(c["status"]=="completed" for c in checks) else "partial","engine":"android-static-readiness","engineVersion":VERSION,"evidence":{"checks":checks,"fixtureHashes":{"dex":hashlib.sha256(dex).hexdigest(),"elf":hashlib.sha256(elf).hexdigest()}},"limitations":["Owned static fixture checks are not target-wide correctness, external decompiler validation, OS sandboxing, runtime-worker provisioning or license verification."]}


def content_candidates(data):
    """Bounded signature hints, never a universal type or parser-validity oracle."""
    candidates=[]
    def add(fmt, reason):
        candidates.append({"format":fmt,"evidence":reason,"validation":"signature-only-candidate"})
    if data.startswith(b"dex\n") or data.startswith(b"cdex"):add("dex","DEX-family prefix at offset zero; validation is separate")
    if data.startswith(b"\x7fELF"):add("elf","ELF magic at offset zero; not structural validation")
    if data.startswith(b"MZ"):add("pe","DOS MZ prefix; not proof of a PE executable")
    if data.startswith(b"\xca\xfe\xba\xbe"):
        add("jvm-class","CAFEBABE can denote a Java class or a Mach-O fat container")
        add("macho-fat","CAFEBABE is shared; no language or architecture inferred")
    if data[:4] in (b"\xce\xfa\xed\xfe",b"\xcf\xfa\xed\xfe",b"\xfe\xed\xfa\xce",b"\xfe\xed\xfa\xcf",b"\xbe\xba\xfe\xca",b"\xbf\xba\xfe\xca",b"\xca\xfe\xba\xbf"):add("macho","Mach-O-family magic; no load-command validation")
    if data.startswith(b"\x00asm"):add("wasm","WebAssembly magic; no version/module validation")
    if data.startswith(b"\x1f\x8b"):add("gzip","gzip prefix; bounded decompression is separate")
    elif len(data)>=2 and data[0]&15==8 and int.from_bytes(data[:2],"big")%31==0:add("zlib","zlib-compatible header; bounded decompression is separate")
    # is_zipfile inspects the bounded EOCD tail. Parsing/members still pass the existing strict traversal.
    if data.startswith((b"PK\x03\x04",b"PK\x05\x06")) or zipfile.is_zipfile(io.BytesIO(data)):
        add("zip","ZIP prefix or end-directory candidate; strict central-directory/member checks are separate")
    return candidates


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
    identify_formats = config.get("identify_formats") is True
    records, warnings, dexes = [], [], []
    native_artifacts = []
    jni_trace = options.get("jni_trace")
    native_bytes = {}
    dex_data = []
    selected_code = []
    native_work = [0]
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
        candidates = content_candidates(data) if identify_formats else []
        zip_candidate = any(c["format"] == "zip" for c in candidates)
        if identify_formats:
            record["identification"] = {"candidates":candidates,"ambiguous":len(candidates)>1,"status":"candidate" if candidates else "unknown","filenameTrusted":False}
        if not zip_candidate and (data.startswith(b"dex\n") or data.startswith(b"cdex")):
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
                if request["action"]=="android_method_code":dex_data.append((identity,data))
            except (ValueError, struct.error, UnicodeError) as exc:
                record.update(validation="candidate-rejected-or-unsupported", reason=str(exc))
        elif not zip_candidate and data.startswith(b"\x7fELF"):
            record["format"] = "elf"
            record["validation"] = "signature-only-candidate"
            record["reason"] = "Use native_inventory for LIEF structural evidence; no ELF execution"
            if request["action"]=="android_relationships" or config.get("inspect_native"):
                try:
                    if native_work[0]>=32:truncated[0]=True;raise ValueError("Native artifact parser budget")
                    native_work[0]+=1
                    meta,_=native_metadata(data,identity,limit)
                    record.update(validation="LIEF-parsed-bounded-file-mappings",native=meta)
                    native_artifacts.append(record)
                    if jni_trace and (not jni_trace.get("native_artifact") or label==jni_trace["native_artifact"]):native_bytes[identity]=data
                    if meta["functionsTruncated"] or meta["jniExportsTruncated"]:truncated[0]=True
                except ImportError:record["reason"]="LIEF missing; ELF remains an unverified signature candidate"
                except (ValueError,RuntimeError) as exc:record["reason"]=str(exc)

        elif zip_candidate or data.startswith(b"PK\x03\x04") or data.startswith(b"PK\x05\x06"):
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
        if identify_formats:
            # A parsed ZIP says nothing about another candidate format in the same bytes.
            ident=record["identification"]
            ident["status"] = "ambiguous" if ident["ambiguous"] else "unknown" if not candidates else "bounded-validated" if record["validation"] in ("integrity-and-bounded-structure","central-directory-checked","bounded-decompression") else "candidate"
            if record["format"] == "opaque" and len(candidates)==1:
                record["format"]=candidates[0]["format"]
                record["validation"]="signature-only-candidate"
        if record["format"] == "opaque":
            sample = data[:1048576]
            counts = [0]*256
            for byte in sample:
                counts[byte] += 1
            record["sampleEntropy"] = -sum((c/len(sample))*math.log2(c/len(sample)) for c in counts if c) if sample else 0
            record["entropyInterpretation"] = "Not evidence of encryption; compressed/random data can also have high entropy"
        # Carve standard DEX candidates from otherwise opaque/native payloads, bounded.
        if record["format"] in ("opaque", "elf", "pe", "macho", "wasm") and depth < max_depth:
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
        elif record["format"] in ("opaque", "elf", "pe", "macho", "wasm") and depth >= max_depth:
            truncated[0] = True
    scan(root, "input")
    selected = []
    relationships = []
    selector = options.get("method")
    if (jni_trace or request["action"] in ("android_method","android_method_code")) and not selector:
        raise ValueError("android_method requires exact class_descriptor, name and descriptor")
    native_short_counts={}
    for artifact,methods in dexes:
        for method in methods:
            if method.get("native"):
                short="Java_"+jni_escape(method["classDescriptor"][1:-1])+"_"+jni_escape(method["name"])
                native_short_counts[short]=native_short_counts.get(short,0)+1
    for artifact, methods in dexes:
        for method in methods:
            method["id"] = stable(artifact["id"], method["methodIndex"])
            method["artifactId"] = artifact["id"]
            if selector and (method["classDescriptor"],method["name"],method["descriptor"]) == (selector["class_descriptor"],selector["name"],selector["descriptor"]):
                selected.append(method)
                if request["action"]=="android_method_code":
                    try:selected_code.append(dict(artifactId=artifact["id"],methodId=method["id"],**selected_dex_code(next(d for a,d in dex_data if a==artifact["id"]),selector,limit)))
                    except ImportError:selected_code.append({"artifactId":artifact["id"],"methodId":method["id"],"status":"blocked","reason":"Androguard is not installed"})
            if method.get("native"):
                relationship_count += 1
            matches_selector=not jni_trace or (method["classDescriptor"],method["name"],method["descriptor"]) == (selector["class_descriptor"],selector["name"],selector["descriptor"])
            if method.get("native") and matches_selector and len(relationships) < limit:
                short = "Java_" + jni_escape(method["classDescriptor"][1:-1]) + "_" + jni_escape(method["name"])
                parameters = method["descriptor"].split(")",1)[0][1:]
                relationships.append({"id": stable(method["id"], "jni-name"), "methodId": method["id"], "artifactId": artifact["id"], "kind": "jni-name-candidate", "shortName": short, "longName": short + "__" + jni_escape(parameters), "confidence": "derived-name-only", "verifiedBinding": False})
    matches=[]
    export_match_count=0
    short_counts={}
    for relationship in relationships:short_counts[relationship["shortName"]]=short_counts.get(relationship["shortName"],0)+1
    for relationship in relationships:
        for lib in native_artifacts:
            if jni_trace and jni_trace.get("native_artifact") and lib["logicalPath"]!=jni_trace["native_artifact"]:continue
            for symbol in lib["native"]["jniExports"]:
                if symbol["name"] not in (relationship["shortName"],relationship["longName"]):continue
                export_match_count+=1
                if len(matches)>=limit:truncated[0]=True;continue
                matches.append({"id":stable(relationship["methodId"],symbol["id"]),"kind":"jni-export-match-candidate","methodId":relationship["methodId"],"artifactId":relationship["artifactId"],"nativeArtifactId":lib["id"],"nativeSymbolId":symbol["id"],"symbol":symbol["name"],"addressHex":symbol["addressHex"],"confidence":"static-export-name-match","overloadAmbiguous":symbol["name"]==relationship["shortName"] and ((native_short_counts[relationship["shortName"]]>1 if jni_trace else short_counts[relationship["shortName"]]>1 or relationship_count>limit)),"verifiedBinding":False})
    relationships.extend(matches)
    for artifact, _ in dexes:
        for method in artifact["dex"]["methods"] + artifact["dex"]["loaderReferences"]:
            method["id"] = stable(artifact["id"],method["methodIndex"])
            method["artifactId"] = artifact["id"]
    evidence = {"schemaVersion": 1, "artifacts": records, "relationships": relationships,
                "relationshipCount": relationship_count + export_match_count, "derivedNameCount": relationship_count, "exportMatchCount": export_match_count, "relationshipsTruncated": relationship_count > limit or export_match_count > limit,
                "coverage": {"processedBytes": work[0], "parsedMethodCount": method_work[0], "maxParsedMethods": MAX_TOTAL_METHODS, "maxDepth": max_depth, "artifactLimit": artifact_limit, "truncated": truncated[0]}, "warnings": warnings[:64]}
    limitations = ["Static input processing only; no target execution, arbitrary key recovery or full devirtualization.",
                   "DEX validation covers integrity and bounded structures, not full bytecode verification. Modified/unsupported DEX remains a candidate.",
                   "Loader references are pool references, not proven executed calls. JNI names are candidates, not observed RegisterNatives bindings.",
                   "ELF without LIEF remains a signature candidate; LIEF export/name matches remain static candidates, not RegisterNatives observations. Nested inspection is bounded."]
    if identify_formats:
        evidence["identification"]={"protocol":"cline-artifact-identification/v1","contentBased":True,"observedExecution":False,"supportedCandidates":["dex","elf","zip","gzip","zlib","pe","jvm-class","macho-fat","macho","wasm"],"unknownCount":sum(r["identification"]["status"]=="unknown" for r in records),"ambiguousCount":sum(r["identification"]["ambiguous"] for r in records),"candidateCount":sum(r["identification"]["status"]=="candidate" for r in records)}
        if any(r["identification"]["status"] != "bounded-validated" for r in records):truncated_identification=True
        else:truncated_identification=False
        limitations.append("Content signatures are candidates, not full PE/JVM/Mach-O/Wasm verification or proof all embedded formats were found. Conflicts are preserved; ZIP structure does not validate another candidate. Filenames are untrusted labels; unknown bytes are not a successful identification.")
    else:truncated_identification=False
    status = "partial" if truncated_identification or truncated[0] or warnings or any("rejected" in r["validation"] or "candidate" in r["validation"] for r in records) else "completed"
    if jni_trace or request["action"] in ("android_method","android_method_code"):
        evidence["selectedMethods"] = selected[:limit]
        if selected_code:evidence["selectedCode"]=selected_code
        evidence["selectedMethodCount"] = len(selected)
        evidence["selectedMethodsTruncated"] = len(selected) > limit
        evidence["selectionStatus"] = "found" if selected else "not-found-in-covered-artifacts"
        evidence["ambiguousAcrossArtifacts"] = len(selected) > 1
        status = "partial" if not selected or truncated[0] or len(selected) > limit else status
    if any(c.get("status")=="blocked" or any(m.get("instructionsTruncated") for m in c.get("methods",[])) for c in selected_code):status="partial"
    if relationship_count > limit or any(r.get("dex",{}).get("methodsTruncated") or r.get("dex",{}).get("loaderReferencesTruncated") for r in records):
        status = "partial"
        limitations.append("Method/reference listings truncated; exact selection searches parsed method pools within stated limits.")
    if jni_trace:
        maximum=jni_trace.get("max_candidates",16)
        if type(maximum) is not int or not 1<=maximum<=64:raise ValueError("JNI candidate budget must be 1..64")
        candidate_exports=matches[:maximum]
        trace={"protocol":"cline-fresh-cross-language/v1","status":"partial","observedExecution":False,"methodSelector":selector,"nativeArtifactSelector":jni_trace.get("native_artifact"),"selectedMethodCount":len(selected),"selectedMethods":selected[:20],"candidateExports":candidate_exports,"candidateCount":len(matches),"candidatesTruncated":len(matches)>maximum or export_match_count>limit,"nativeTraversal":{"status":"not-started","reason":"Requires one retained defined native method and one unambiguous retained JNI export candidate"},"bindingVerified":False,"registrationStatus":"unresolved-not-observed"}
        if len(selected)==1 and selected[0].get("native") and len(matches)==1 and not matches[0]["overloadAmbiguous"]:
            candidate=matches[0];data=native_bytes.get(candidate["nativeArtifactId"])
            if data is not None:
                try:
                    meta,functions=native_metadata(data,candidate["nativeArtifactId"],limit)
                    roots=[fn for fn in functions if fn["id"]==candidate["nativeSymbolId"]]
                    if len(roots)!=1:raise ValueError("Exact retained JNI ELF symbol is missing or ambiguous")
                    budget=native_call_budget(jni_trace.get("native_calls") or {})
                    selected_root=roots[0];disassembly=disassemble_selected(data,selected_root,min(4096,budget["max_total_bytes"]),meta["segments"])
                    graph=native_call_traversal(data,selected_root,disassembly,functions,meta,budget,4096)
                    trace["nativeTraversal"]={"status":"partial","scope":"selected-static-export-candidate-only","nativeArtifactSha256":hashlib.sha256(data).hexdigest(),"callGraph":graph}
                except ImportError:trace["nativeTraversal"]={"status":"blocked","reason":"Required static LIEF/Capstone engine missing; no execution fallback"}
                except (ValueError,RuntimeError) as exc:trace["nativeTraversal"]={"status":"partial","reason":str(exc)[:1000]}
        evidence["crossLanguageTrace"]=trace
        status="partial"
        limitations.append("Fresh JNI trace uses an exact parsed DEX native declaration and static JNI export-name candidates only. Retained candidate uniqueness is not global binding proof; ABI/library loading, RegisterNatives, aliases and runtime reachability remain unresolved. Optional native graph starts at a candidate export, never a proven Java call path.")
    return {"protocol": "cline-advanced-analysis/v1", "status": status, "engine": "android-static", "engineVersion": VERSION,
            "input": {"sha256": hashlib.sha256(root).hexdigest(), "bytes": len(root), "format": records[0]["format"]}, "evidence": evidence, "limitations": limitations}


# Fixed framework signatures, not user-supplied executable recipes. These are
# declaration candidates only; OEM/framework dispatch and registration are outside scope.
CALLBACKS = {
    'application': [('onCreate','()V'),('onTerminate','()V'),('onLowMemory','()V'),('onTrimMemory','(I)V'),('onConfigurationChanged','(Landroid/content/res/Configuration;)V')],
    'activity': [('onCreate','(Landroid/os/Bundle;)V'),('onCreate','(Landroid/os/Bundle;Landroid/os/PersistableBundle;)V'),('onStart','()V'),('onResume','()V'),('onPause','()V'),('onStop','()V'),('onDestroy','()V'),('onRestart','()V'),('onNewIntent','(Landroid/content/Intent;)V'),('onActivityResult','(IILandroid/content/Intent;)V'),('onRequestPermissionsResult','(I[Ljava/lang/String;[I)V'),('onSaveInstanceState','(Landroid/os/Bundle;)V')],
    'service': [('onCreate','()V'),('onDestroy','()V'),('onStartCommand','(Landroid/content/Intent;II)I'),('onBind','(Landroid/content/Intent;)Landroid/os/IBinder;'),('onUnbind','(Landroid/content/Intent;)Z'),('onRebind','(Landroid/content/Intent;)V'),('onTaskRemoved','(Landroid/content/Intent;)V')],
    'receiver': [('onReceive','(Landroid/content/Context;Landroid/content/Intent;)V')],
    'provider': [('onCreate','()Z'),('query','(Landroid/net/Uri;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;'),('insert','(Landroid/net/Uri;Landroid/content/ContentValues;)Landroid/net/Uri;'),('update','(Landroid/net/Uri;Landroid/content/ContentValues;Ljava/lang/String;[Ljava/lang/String;)I'),('delete','(Landroid/net/Uri;Ljava/lang/String;[Ljava/lang/String;)I'),('getType','(Landroid/net/Uri;)Ljava/lang/String;')],
}
ANDROID_NS = '{http://schemas.android.com/apk/res/android}'


def workflow_zip(target, budget):
    with open(target, 'rb') as f:
        data = f.read(MAX_INPUT+1)
    if len(data)>MAX_INPUT: raise ValueError('Android workflow input exceeds 64 MiB')
    # Preflight central-directory framing before ZipFile allocates entry objects.
    # Ordinary single-disk ZIP only; no ZIP64, multi-volume or appended payloads.
    end=data.rfind(b'PK\x05\x06',max(0,len(data)-65557))
    if end<0 or end+22>len(data):raise ValueError('Android ZIP end record required')
    disk,cd_disk,disk_count,total,cd_size,cd_offset,comment=struct.unpack_from('<4H2IH',data,end+4)
    if disk or cd_disk or disk_count!=total or total>10000 or end+22+comment!=len(data) or cd_offset+cd_size!=end:
        raise ValueError('Unsupported or oversized Android ZIP central directory')
    cursor=cd_offset;count=0
    while cursor<end:
        count+=1
        if count>10000 or cursor+46>end or data[cursor:cursor+4]!=b'PK\x01\x02':raise ValueError('Android ZIP central entry budget/framing')
        name_size,extra_size,comment_size=struct.unpack_from('<3H',data,cursor+28)
        if name_size>4096:raise ValueError('Android ZIP encoded name exceeds budget')
        cursor+=46+name_size+extra_size+comment_size
    if cursor!=end or count!=total:raise ValueError('Android ZIP central entry count/framing mismatch')
    archive = zipfile.ZipFile(io.BytesIO(data))
    entries = archive.infolist()
    if len(entries)>10000: raise ValueError('Android ZIP entry budget exceeded')
    names = set()
    for e in entries:
        if len(e.filename)>1024 or '\\' in e.filename or e.filename.startswith('/') or any(p in ('','.', '..') for p in e.filename.rstrip('/').split('/')):
            raise ValueError('Noncanonical Android ZIP path')
        key=e.filename.casefold()
        if key in names: raise ValueError('Duplicate or case-aliased Android ZIP member')
        names.add(key)
        if e.flag_bits & 1: raise ValueError('Encrypted Android ZIP entries unsupported')
        mode = (e.external_attr >> 16) & 0xf000
        if mode not in (0, 0x4000, 0x8000): raise ValueError('Android ZIP special entries unsupported')
    return data,archive,entries


def workflow_member(archive, entry, budget, maximum=MAX_CHILD):
    if entry.file_size>maximum or entry.file_size>max(1,entry.compress_size)*100:
        raise ValueError('Android ZIP member size or expansion budget exceeded')
    if budget[0]+entry.file_size>MAX_WORK: raise ValueError('Android aggregate expanded byte budget exceeded')
    with archive.open(entry) as f: data=f.read(maximum+1)
    if len(data)!=entry.file_size or len(data)>maximum: raise ValueError('Android ZIP member size changed')
    budget[0]+=len(data)
    return data


def workflow_xml(data):
    if len(data)>1024*1024: raise ValueError('Android XML exceeds 1 MiB parse budget')
    encoding='utf8-text'
    if data[:4]==b'\x03\x00\x08\x00':
        from androguard.core.axml import AXMLPrinter
        printer=AXMLPrinter(data)
        if not printer.is_valid(): raise ValueError('Android binary XML rejected by decoder')
        data=printer.get_xml()
        encoding='androguard-binary-xml'
        if not isinstance(data,bytes) or len(data)>1024*1024: raise ValueError('Decoded Android XML exceeds byte budget')
    # Reject DTD/entities before a standard XML parser. Decode UTF-8 strictly so
    # UTF-16/interleaved-NUL declarations cannot bypass this policy.
    text=data.decode('utf-8-sig',errors='strict')
    if '\x00' in text or re.search(r'<!\s*(?:DOCTYPE|ENTITY)',text,re.I):
        raise ValueError('Android XML DTD/entities/NULs are not supported')
    declaration=re.match(r'\s*<\?xml\s+[^?]*encoding\s*=\s*[\"\x27]([^\"\x27]+)',text,re.I)
    if declaration and declaration[1].lower() not in ('utf-8','utf8','us-ascii'):
        raise ValueError('Only UTF-8 Android XML supported')
    root=ET.fromstring(text)
    stack=[(root,0)];count=0
    while stack:
        node,depth=stack.pop();count+=1
        if count>20000 or depth>64: raise ValueError('Android XML node/depth budget exceeded')
        stack.extend((child,depth+1) for child in node)
    return root,encoding,count


def normalized_android_class(package, name):
    if not isinstance(name,str) or not name: return None
    value=package+name if name.startswith('.') else name if '.' in name else package+'.'+name
    if len(value)>1000 or not re.fullmatch(r'[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*',value): return None
    return 'L'+value.replace('.','/')+';'


def manifest_components(root):
    if root.tag!='manifest': raise ValueError('Android manifest root required')
    package=root.get('package','')
    if not re.fullmatch(r'[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*',package): raise ValueError('Literal manifest package required')
    applications=root.findall('application')
    if len(applications)!=1: raise ValueError('Exactly one manifest application required')
    app=applications[0];rows=[]
    for node in [app]+list(app):
        kind=node.tag
        if kind not in set(CALLBACKS)|{'activity-alias'}: continue
        name=node.get(ANDROID_NS+'name')
        if kind=='application' and name is None: continue  # framework default, not an app-defined class
        selected=node.get(ANDROID_NS+'targetActivity') if kind=='activity-alias' else name
        rows.append({'componentIndex':len(rows),'kind':kind,'declaredName':(name or '')[:1000],
          'classDescriptor':normalized_android_class(package,selected),'aliasTarget':(selected or '')[:1000] if kind=='activity-alias' else None,
          'enabledDeclared':node.get(ANDROID_NS+'enabled'),'applicationEnabledDeclared':app.get(ANDROID_NS+'enabled'),
          'exportedDeclared':node.get(ANDROID_NS+'exported'),'permissionDeclared':node.get(ANDROID_NS+'permission'),
          'intentFilterCount':len(node.findall('intent-filter'))})
    return package,rows


def entrypoint_candidates(components, classes, methods, maximum_depth, maximum_components, maximum_results):
    by_class={};by_method={}
    for c in classes:by_class.setdefault(c['descriptor'],[]).append(c)
    for m in methods:
        if m.get('defined'):by_method.setdefault((m['artifactId'],m['classDescriptor'],m['name'],m['descriptor']),[]).append(m)
    details=[];candidates=[];reasons={}
    for component in components[:maximum_components]:
        row=dict(component);kind='activity' if row['kind']=='activity-alias' else row['kind']
        pending=set(CALLBACKS[kind]);current=row['classDescriptor'];seen=set();row['candidateCount']=0;row['hierarchy']=[];row['ambiguousMethodCount']=0
        reason='class-name-unresolved'
        for depth in range(maximum_depth+1):
            if not current:break
            if current in seen:reason='hierarchy-cycle';break
            seen.add(current)
            definitions=by_class.get(current,[])
            if len(definitions)!=1:reason='ambiguous-class' if definitions else 'class-outside-covered-dex';break
            cls=definitions[0];row['hierarchy'].append({'classDescriptor':current,'artifactId':cls['artifactId'],'depth':depth})
            for signature in sorted(pending):
                matches=by_method.get((cls['artifactId'],current,*signature),[])
                if len(matches)>1:row['ambiguousMethodCount']+=1;pending.remove(signature);continue
                if not matches:continue
                method=matches[0];flags=method.get('accessFlags',0)
                # Static/private declarations do not override a framework callback.
                if flags & (0x2|0x8):continue
                pending.remove(signature)
                if flags & 0x400:continue  # abstract declaration is not a concrete handler
                row['candidateCount']+=1
                candidates.append({'componentIndex':row['componentIndex'],'componentKind':row['kind'],
                    'declaredClass':row['classDescriptor'],'declaringClass':current,'name':signature[0],'descriptor':signature[1],
                    'methodIndex':method['methodIndex'],'artifactId':cls['artifactId'],'artifactSha256':cls['artifactSha256'],
                    'inheritedDepth':depth,'native':method.get('native',False),'codeOffset':method.get('codeOffset',0),
                    'byteFingerprint':method.get('byteFingerprint'),'confidence':'manifest-and-exact-defined-signature-candidate',
                    'dispatchVerified':False,'executionObserved':False})
            current=cls['superclass']
            reason='hierarchy-root-reached' if current is None else 'max-depth' if depth==maximum_depth else 'class-outside-covered-dex'
        row['searchStopped']=reason;row['unmatchedCatalogSignatures']=len(pending)
        reasons[reason]=reasons.get(reason,0)+1;details.append(row)
    full_hash=hashlib.sha256(json.dumps(candidates,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    selected=[];used=0
    for candidate in candidates[:maximum_results]:
        size=len(json.dumps(candidate,ensure_ascii=True).encode())
        if used+size>98304:break
        selected.append(candidate);used+=size
    return {'components':details,'componentCount':len(components),'componentsTruncated':len(components)>maximum_components,
        'candidates':selected,'candidateCount':len(candidates),'candidatesTruncated':len(selected)<len(candidates),
        'candidateSetSha256':full_hash,'searchStopCounts':reasons,'catalog':CALLBACKS}


def android_entrypoints(request):
    opts=request.get('options') or {}
    if set(opts)-{'entrypoints'}: raise ValueError('Android entrypoints rejects unrelated options')
    opts=opts.get('entrypoints') or {}
    if set(opts)-{'max_depth','max_components','max_dex_files'}: raise ValueError('Unknown entrypoint budget')
    def budget(name,default,minimum,maximum):
        v=opts.get(name,default)
        if type(v) is not int or not minimum<=v<=maximum:raise ValueError('Invalid Android entrypoint '+name)
        return v
    depth=budget('max_depth',8,0,16);component_limit=budget('max_components',64,1,128);dex_limit=budget('max_dex_files',32,1,32)
    limit=request.get('limit',200)
    if type(limit) is not int or not 1<=limit<=1000:raise ValueError('Invalid Android candidate limit')
    limit=min(limit,200);work=[0]
    data,archive,entries=workflow_zip(request['target'],work)
    with archive:
        manifest=[e for e in entries if e.filename=='AndroidManifest.xml' and not e.is_dir()]
        if len(manifest)!=1:raise ValueError('Exact AndroidManifest.xml member required')
        manifest_data=workflow_member(archive,manifest[0],work,1024*1024)
        root,encoding,nodes=workflow_xml(manifest_data);package,components=manifest_components(root)
        dex_entries=sorted([e for e in entries if re.fullmatch(r'classes(?:[2-9]|[1-9][0-9]+)?\.dex',e.filename) and not e.is_dir()],key=lambda e:e.filename)
        classes=[];methods=[];artifacts=[];errors=[];method_count=0
        for entry in dex_entries[:dex_limit]:
            raw=workflow_member(archive,entry,work)
            try:
                if method_count+u32(raw,88)>MAX_TOTAL_METHODS:raise ValueError('Aggregate DEX method budget exceeded')
                meta,parsed=dex_metadata(raw,1,True)
                if len(classes)+len(meta['classes'])>50000:raise ValueError('Aggregate DEX class budget exceeded')
                method_count+=len(parsed);sha=hashlib.sha256(raw).hexdigest();identity=stable(entry.filename,sha)
                artifacts.append({'id':identity,'logicalPath':entry.filename,'sha256':sha,'bytes':len(raw),'definedClasses':len(meta['classes']),'methods':len(parsed)})
                classes.extend(dict(c,artifactId=identity,artifactSha256=sha) for c in meta['classes'])
                methods.extend(dict(m,artifactId=identity) for m in parsed)
            except (ValueError,struct.error,UnicodeError) as exc:
                errors.append({'logicalPath':entry.filename,'sha256':hashlib.sha256(raw).hexdigest(),'reason':str(exc)[:200]})
        result=entrypoint_candidates(components,classes,methods,depth,component_limit,limit)
        result.update(protocol='cline-android-entrypoints/v1',package=package,manifestSha256=hashlib.sha256(manifest_data).hexdigest(),manifestEncoding=encoding,
            manifestNodes=nodes,artifacts=artifacts,rejectedDex=errors,observedExecution=False,dispatchVerified=False,
            coverage={'dexMembers':len(dex_entries),'parsedDexMembers':len(artifacts),'dexTruncated':len(dex_entries)>dex_limit,'parsedMethods':method_count,'parsedClasses':len(classes),
                      'expandedBytes':work[0],'standardRootDexOnly':True,'ignoredNonstandardDexMembers':sum(e.filename.endswith('.dex') and e not in dex_entries for e in entries),'maxDepth':depth,'maxComponents':component_limit,'maxCandidates':limit})
    output={'protocol':'cline-advanced-analysis/v1','status':'partial','engine':'android-static','engineVersion':VERSION,
        'input':{'sha256':hashlib.sha256(data).hexdigest(),'bytes':len(data),'format':'apk-zip'},'evidence':result,
        'limitations':['Manifest declarations plus supported exact DEX signatures and bounded superclass search only; not whole-program reachability, dispatch or observed execution.',
        'Application/Activity/Service/Receiver/Provider fixed callback catalog; aliases resolve their declared target. Listeners, fragments, dynamic receivers, Compose, reflection, native registration and framework/OEM-specific callbacks remain unresolved.',
        'Exported/enabled/permission values are untrusted declarations, not effective permission or SDK-default conclusions. Resource-referenced names remain unresolved. Missing, duplicate, rejected and budget-excluded DEX classes can hide or invalidate candidates.',
        'Superclass paths do not establish Android framework type compatibility or runtime dispatch. Exact candidates do not imply full bytecode validation, valid APK, signature verification or device compatibility. No extraction, signing, installation or execution.']}
    if len(json.dumps(output,ensure_ascii=True).encode())>262144:raise ValueError('Android entrypoint output exceeds 256 KiB; narrow component budget')
    return output


def xml_structure_hash(data):
    root,encoding,count=workflow_xml(data)
    def tree(node):return [node.tag,sorted(node.attrib.items()),node.text,node.tail,[tree(child) for child in node]]
    return {'sha256':hashlib.sha256(json.dumps(tree(root),ensure_ascii=True,separators=(',',':')).encode()).hexdigest(),'encoding':encoding,'nodes':count,
            'model':'namespace-expanded-element-attribute-sorted-child-order-text-tail-preserved-comments-omitted/v1'}


def android_resources(request):
    if request.get('options'):raise ValueError('Android resource comparison rejects unrelated options')
    limit=request.get('limit',200)
    if type(limit) is not int or not 1<=limit<=1000:raise ValueError('Invalid resource detail limit')
    limit=min(limit,200);work=[0];inventories=[];inputs=[]
    for target in [request['target'],request['compare_target']]:
        data,archive,entries=workflow_zip(target,work);inputs.append({'sha256':hashlib.sha256(data).hexdigest(),'bytes':len(data),'format':'apk-zip'})
        inventory={}
        with archive:
            for entry in entries:
                if entry.is_dir():continue
                raw=workflow_member(archive,entry,work)
                row={'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw)}
                if entry.filename=='AndroidManifest.xml' or entry.filename.startswith('res/') and entry.filename.endswith('.xml'):
                    try:row['xmlStructure']=xml_structure_hash(raw)
                    except (ImportError,ValueError,ET.ParseError,UnicodeError,RuntimeError) as exc:row['xmlStructure']={'status':'unavailable','reason':str(exc)[:160]}
                inventory[entry.filename]=row
        inventories.append(inventory)
    left,right=inventories;changes=[];counts={}
    for name in sorted(set(left)|set(right)):
        a,b=left.get(name),right.get(name)
        if a and b and a['sha256']==b['sha256']:continue
        category='manifest' if name=='AndroidManifest.xml' else 'resources' if name.startswith('res/') or name=='resources.arsc' else 'assets' if name.startswith('assets/') else 'dex' if re.fullmatch(r'classes(?:[2-9]|[1-9][0-9]+)?\.dex',name) else 'native' if name.startswith('lib/') and name.endswith('.so') else 'other'
        kind='added' if a is None else 'removed' if b is None else 'changed';counts[category]=counts.get(category,0)+1
        row={'path':name,'kind':kind,'category':category,'before':a,'after':b}
        if a and b and a.get('xmlStructure',{}).get('sha256') and b.get('xmlStructure',{}).get('sha256'):
            row['parsedXmlStructureEqual']=a['xmlStructure']['sha256']==b['xmlStructure']['sha256']
        changes.append(row)
    selected=[];used=0
    for row in changes[:limit]:
        size=len(json.dumps(row,ensure_ascii=True).encode())
        if used+size>131072:break
        selected.append(row);used+=size
    hashes=[hashlib.sha256(json.dumps(inv,sort_keys=True,separators=(',',':')).encode()).hexdigest() for inv in inventories]
    return {'protocol':'cline-advanced-analysis/v1','status':'partial','engine':'android-static','engineVersion':VERSION,'input':inputs[0],
        'evidence':{'protocol':'cline-android-resource-comparison/v1','compareInput':inputs[1],'effect':'read','observedExecution':False,'published':False,
            'baselineFiles':len(left),'candidateFiles':len(right),'baselineInventorySha256':hashes[0],'candidateInventorySha256':hashes[1],
            'identicalEntryBytes':all(left.get(k,{}).get('sha256')==right.get(k,{}).get('sha256') for k in set(left)|set(right)),
            'changedFiles':len(changes),'categoryCounts':counts,'changes':selected,'changesTruncated':len(selected)<len(changes),
            'changeSetSha256':hashlib.sha256(json.dumps(changes,sort_keys=True,separators=(',',':')).encode()).hexdigest(),
            'expandedBytes':work[0],'maxDetailRows':limit},
        'limitations':['Every covered regular ZIP member is read and SHA256-hashed, not compared by ZIP CRC alone; duplicate/case-aliased, encrypted, oversized, over-expanded or special entries fail closed. No extraction or execution.',
            'Optional XML structural fingerprints expand namespaces and sort attributes, retaining element/child order and text/tails, omitting comments. Binary XML requires Androguard; unsupported XML remains byte-only with a reason. This is not Android resource-table/configuration resolution or semantic equivalence.',
            'Ordinary single-disk ZIP only, not ZIP64 or appended payloads. 64 MiB per archive, 10000 entries per archive, 16 MiB per entry, 100:1 expansion and 128 MiB expanded aggregate across both; XML 1 MiB/20000 nodes/depth 64; details 200 rows/128 KiB. Missing detail is explicit; counts/hash retain the bounded change set.',
            'ZIP metadata/directory/order/signature validity, resources.arsc semantics, DEX/native API/ABI, behavioral equivalence and device compatibility are not verified. Targets are read once; not an atomic filesystem snapshot.']}


def main():
    try:
        request = json.loads(sys.argv[1])
        if request["action"] not in ("artifact_discovery", "android_relationships", "android_method", "android_method_code", "native_function", "analysis_readiness", "android_entrypoints", "android_resources"):
            raise ValueError("Unsupported Android investigation action")
        result = analysis_readiness() if request["action"]=="analysis_readiness" else native_selection(request) if request["action"]=="native_function" else android_entrypoints(request) if request["action"]=="android_entrypoints" else android_resources(request) if request["action"]=="android_resources" else investigate(request)
        output = json.dumps(result, ensure_ascii=True, separators=(",", ":"))
        if len(output.encode()) > 900000:
            raise ValueError("Android evidence exceeds bounded output; reduce max_artifacts/limit")
        print(output)
    except ImportError:
        print(json.dumps({"protocol":"cline-advanced-analysis/v1","status":"blocked","engine":"android-static","engineVersion":VERSION,"evidence":{"reason":"Required static engine is not installed"},"limitations":["No execution verification is claimed"]}))
    except Exception as exc:
        print(json.dumps({"protocol":"cline-advanced-analysis/v1", "status":"failed", "engine":"android-static", "engineVersion":VERSION, "evidence":{"reason":str(exc)}, "limitations":["No successful analysis implied by failure"]}))


if __name__ == "__main__":
    main()
