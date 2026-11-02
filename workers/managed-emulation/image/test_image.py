import gzip
import hashlib
import io
import json
from pathlib import Path
import stat
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE), str(HERE.parent)]
import build_image as image
import provision_boot
import smoke_boot


def tar(entries):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as stream:
        for path, kind, body in entries:
            entry = tarfile.TarInfo(path)
            entry.mode = 0o6777
            if kind == "file":
                entry.size = len(body)
                stream.addfile(entry, io.BytesIO(body))
            else:
                entry.type = {"symlink": tarfile.SYMTYPE, "hardlink": tarfile.LNKTYPE, "fifo": tarfile.FIFOTYPE, "directory": tarfile.DIRTYPE}[kind]
                entry.linkname = body
                stream.addfile(entry)
    return output.getvalue()


def entries(data):
    raw, offset, result = gzip.decompress(data), 0, {}
    while True:
        header = raw[offset:offset+110]
        assert header[:6] == b"070701"
        values = [int(header[6+i*8:14+i*8],16) for i in range(13)]
        start = offset + 110
        name = raw[start:start+values[11]-1].decode()
        data_start = (start + values[11] + 3) // 4 * 4
        body = raw[data_start:data_start+values[6]]
        offset = (data_start + values[6] + 3) // 4 * 4
        if name == "TRAILER!!!":
            break
        result[name] = (values, body)
    return result


class ArchiveTests(unittest.TestCase):
    def test_regular_content_and_modes_are_normalized_without_host_extraction(self):
        nodes = image.archive(tar([("usr/bin/a", "file", b"owned")]))
        self.assertEqual(nodes["usr/bin/a"], image.Node("file",0o755,b"owned"))

    def test_unsafe_paths_duplicate_members_and_special_files_fail(self):
        for name in ["/host", "../host", "a/../host", "a//host", "a\\host"]:
            with self.subTest(name=name), self.assertRaises(ValueError):
                image.archive(tar([(name,"file",b"x")]))
        for data in [tar([("a","file",b"a"),("a","file",b"b")]), tar([("fifo","fifo","")])]:
            with self.assertRaises(ValueError):
                image.archive(data)

    def test_in_image_symlinks_and_hardlinks_are_virtual_only(self):
        nodes = image.archive(tar([("usr/bin/a","file",b"same"),("usr/bin/b","hardlink","usr/bin/a"),("bin","symlink","usr/bin")]))
        self.assertEqual(nodes["usr/bin/a"].data,nodes["usr/bin/b"].data)
        self.assertEqual(image.canonical("bin/a",nodes),"usr/bin/a")
        self.assertEqual(image.link_target("usr/lib/a","../../lib/b"),"lib/b")
        self.assertEqual(image.link_target("usr/lib/a","/lib/b"),"lib/b")

    def test_escaping_links_cycles_and_non_file_hardlinks_fail(self):
        for data in [tar([("a","symlink","../outside")]), tar([("a","hardlink","b"),("b","hardlink","a")]), tar([("a","directory",""),("b","hardlink","a")])]:
            with self.assertRaises(ValueError): image.archive(data)
        with self.assertRaises(ValueError): image.canonical("a/file",{"a":image.Node("symlink",0o777,b"a")})
        with self.assertRaises(ValueError): image.canonical("a/file",{"a":image.Node("file",0o644,b"x")})

    def test_content_and_member_budgets_are_enforced(self):
        with mock.patch.object(image,"MAX_FILE",3), self.assertRaises(ValueError):
            image.archive(tar([("a","file",b"long")]))
        with mock.patch.object(image,"MAX_ENTRIES",1), self.assertRaises(ValueError):
            image.archive(tar([("a","file",b"x"),("b","file",b"y")]))

    def test_cpio_is_deterministic_aligned_and_root_owned(self):
        tree={"usr/bin/tool":image.Node("file",0o755,b"abc"),"lib":image.Node("symlink",0o777,b"usr/lib")}
        first=image.cpio(tree)
        self.assertEqual(first,image.cpio(dict(reversed(list(tree.items())))))
        parsed=entries(first)
        self.assertEqual(parsed["usr/bin/tool"][1],b"abc")
        for fields,_ in parsed.values(): self.assertEqual((fields[2],fields[3],fields[5]),(0,0,0))
        self.assertEqual(parsed["lib"][1],b"usr/lib")
        self.assertTrue(stat.S_ISDIR(parsed["usr"][0][1]))

    def test_cpio_cannot_materialize_a_file_through_a_link(self):
        with self.assertRaises(ValueError):
            image.cpio({"lib":image.Node("symlink",0o777,b"usr/lib"),"lib/payload":image.Node("file",0o644,b"x")})

    def test_pinned_package_rejects_modified_or_wrong_size_input(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/"kernel.deb"; path.write_bytes(b"invalid")
            for expected in [{"size":7,"sha256":"00"*32},{"size":8,"sha256":hashlib.sha256(b"invalid").hexdigest()}]:
                with self.assertRaises(ValueError): image.package(path,expected)

    def test_lock_has_immutable_runtime_and_no_installable_claim(self):
        lock=json.loads((HERE/"inputs.lock.json").read_text())
        self.assertRegex(lock["runtimeImage"],r"^docker.io/library/python@sha256:[0-9a-f]{64}$")
        self.assertEqual(lock["platform"],"linux/amd64")
        self.assertEqual(lock["scope"],"development-inert-guest")
        for package in lock["packages"].values():
            self.assertRegex(package["sha256"],r"^[0-9a-f]{64}$")
            self.assertTrue(package["url"].startswith("https://"))

    def test_pruned_modules_retain_transitive_dependencies_not_network_drivers(self):
        wanted=["vsock","hv_sock","hv_vmbus","hv_storvsc","ata_piix","sr_mod","isofs"]
        paths={name:f"kernel/{name}.ko" for name in wanted+["scsi_mod","unrelated_net"]}
        prefix="lib/modules/owned/"
        kernel={prefix+path:image.Node("file",0o644,name.encode()) for name,path in paths.items()}
        def depmod(command,**kwargs):
            root=Path(command[2])/prefix
            text="".join(path+":"+(" kernel/scsi_mod.ko" if key=="hv_storvsc" else "")+"\n" for key,path in paths.items())
            (root/"modules.dep").write_text(text)
            return mock.Mock(returncode=0,stdout=b"")
        with mock.patch.object(image.subprocess,"run",side_effect=depmod):
            result=image.modules(kernel,"owned")
        self.assertIn("usr/"+prefix+"kernel/scsi_mod.ko",result)
        self.assertNotIn("usr/"+prefix+"kernel/unrelated_net.ko",result)
        self.assertNotIn("unrelated_net",result["usr/"+prefix+"modules.dep"].data.decode())

    def test_existing_output_or_non_exact_source_revision_is_never_replaced(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)
            for revision in ["main","a"*40]:
                with self.assertRaises(ValueError): image.build(path,path,path,path,revision)
            self.assertTrue(path.is_dir())



class ColdBootReceiptTests(unittest.TestCase):
    def log(self, **fields):
        value={"fixtureSha256":hashlib.sha256(b"cline-managed-owned-inert-fixture/v1\n").hexdigest(),"vmIsolation":"not-attested","engineReadiness":"not-tested","hypervExchange":"not-tested",**fields}
        return ("CLINE_MANAGED_INERT_BOOT_V1 "+json.dumps(value)+"\r\nCLINE_MANAGED_CREDENTIAL_ABSENT_V1\r\n").encode()

    def test_grub_serial_control_prefix_does_not_hide_actual_guest_receipt(self):
        data=b"\x1b[H\x1b[J\x1b[1;1H"+self.log()
        self.assertEqual(smoke_boot.validate_boot_log(data,0)["engineReadiness"],"not-tested")

    def test_missing_duplicate_failed_or_promoted_boot_is_not_success(self):
        for data,status in [(self.log(),1),(self.log()+self.log(),0),(self.log().replace(b"CREDENTIAL_ABSENT",b"OTHER"),0),
                            (self.log()+b"CLINE_MANAGED_PROBE_UNRESOLVED_V1",0),(self.log(vmIsolation="attested"),0),
                            (self.log(engineReadiness="ready"),0),(self.log(extra="unexpected"),0)]:
            with self.subTest(status=status,data=data),self.assertRaises(ValueError):smoke_boot.validate_boot_log(data,status)

    def test_expired_and_valid_format_fixtures_require_different_exact_markers(self):
        expired=self.log().replace(b"CLINE_MANAGED_CREDENTIAL_ABSENT_V1",b"CLINE_MANAGED_BOOT_REJECTED_V1")
        valid=self.log().replace(b"CLINE_MANAGED_CREDENTIAL_ABSENT_V1",b"CLINE_MANAGED_CREDENTIAL_ACCEPTED_V1\nCLINE_MANAGED_PROBE_UNRESOLVED_V1")
        self.assertEqual(smoke_boot.validate_boot_log(expired,0,"expired")["engineReadiness"],"not-tested")
        self.assertEqual(smoke_boot.validate_boot_log(valid,0,"valid")["hypervExchange"],"not-tested")
        self.assertEqual(smoke_boot.validate_boot_log(valid,0,"native")["hypervExchange"],"not-tested")
        with self.assertRaises(ValueError):smoke_boot.validate_boot_log(expired,0,"native")
        for data,case in [(valid,"expired"),(expired,"valid"),(valid+b"CLINE_MANAGED_PROBE_EXITED_V1","valid"),(valid+b"CLINE_MANAGED_CREDENTIAL_ACCEPTED_V1","valid")]:
            with self.subTest(case=case),self.assertRaises(ValueError):smoke_boot.validate_boot_log(data,0,case)

    def test_duplicate_json_receipt_fields_are_rejected(self):
        data=self.log().replace(b'{"fixtureSha256"',b'{"engineReadiness":"not-tested","fixtureSha256"')
        with self.assertRaises(ValueError):smoke_boot.validate_boot_log(data,0)


class ProvisioningTests(unittest.TestCase):
    def test_actual_exclusive_copy_validates_private_record_before_listener(self):
        with tempfile.TemporaryDirectory() as directory:
            source,target=Path(directory)/"BOOT.JSON",Path(directory)/"boot.json"
            source.write_bytes(b'{"owned":"fixture"}')
            with mock.patch.object(provision_boot,"SOURCE",str(source)), mock.patch.object(provision_boot,"DESTINATION",str(target)), mock.patch.object(provision_boot,"read_boot_config") as validate:
                provision_boot.main()
                validate.assert_called_once_with()
                self.assertEqual(target.read_bytes(),source.read_bytes())
                self.assertEqual(stat.S_IMODE(target.stat().st_mode),0o600)
                with self.assertRaises(FileExistsError): provision_boot.main()

    def test_linked_oversized_or_fifo_media_is_rejected_without_target(self):
        import os
        with tempfile.TemporaryDirectory() as directory:
            directory=Path(directory); original=directory/"original";original.write_bytes(b"x")
            for kind in ["symlink","oversized","fifo"]:
                source,target=directory/kind,directory/(kind+"-target")
                if kind=="symlink":source.symlink_to(original)
                elif kind=="fifo":os.mkfifo(source,0o600)
                else:source.write_bytes(b"x"*1025)
                with self.subTest(kind=kind),mock.patch.object(provision_boot,"SOURCE",str(source)),mock.patch.object(provision_boot,"DESTINATION",str(target)):
                    with self.assertRaises((ValueError,OSError)):provision_boot.main()
                    self.assertFalse(target.exists())


if __name__=="__main__":unittest.main()
