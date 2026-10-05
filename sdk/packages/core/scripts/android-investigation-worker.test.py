import hashlib
import importlib.util
import io
import json
import struct
import tempfile
import unittest
import zipfile
import zlib
from pathlib import Path

HERE = Path(__file__).parent
spec = importlib.util.spec_from_file_location('android_worker', HERE / 'android-investigation-worker.py')
w = importlib.util.module_from_spec(spec)
spec.loader.exec_module(w)


def dex_fixture(with_code=False):
    # Native declaration + referenced (not executed) System.loadLibrary.
    strings = ['LFixture;', 'Ljava/lang/System;', 'V', 'Ljava/lang/String;', 'native_work', 'loadLibrary', 'V', 'VL']
    types = [0, 1, 2, 3]
    offsets = {'strings':112, 'types':144, 'protos':160, 'methods':184, 'classes':200, 'data':232}
    data = bytearray(232)
    string_offsets=[]
    for s in strings:
        string_offsets.append(len(data));data += bytes([len(s)]) + s.encode() + b'\0'
    while len(data)%4:data += b'\0'
    params = len(data);data += struct.pack('<IH',1,3)+b'\0\0'
    codeoff = 0
    if with_code:
        codeoff=len(data);data += struct.pack('<HHHHII',1,0,0,0,0,1) + b'\x0e\x00'  # return-void
    classdata=len(data)
    if with_code:
        value=codeoff;encoded=bytearray()
        while value >= 128:encoded.append((value&127)|128);value >>= 7
        encoded.append(value);data += b'\0\0\1\0\0\1' + encoded
    else:data += b'\0\0\1\0\0\x81\x02\0'  # 0x101 public native
    while len(data)%4:data += b'\0'
    mapoff=len(data)
    entries=[(0,1,0),(1,8,112),(2,4,144),(3,2,160),(5,2,184),(6,1,200),(0x2002,8,232),(0x1001,1,params),(0x2000,1,classdata),(0x1000,1,mapoff)]
    if with_code:entries.insert(8,(0x2001,1,codeoff))
    data += struct.pack('<I',len(entries))
    for kind,count,off in entries:data += struct.pack('<HHII',kind,0,count,off)
    data[:8]=b'dex\n035\0'
    struct.pack_into('<20I',data,32,len(data),112,0x12345678,0,0,mapoff,8,112,4,144,2,160,0,0,2,184,1,200,len(data)-232,232)
    for i,off in enumerate(string_offsets):struct.pack_into('<I',data,112+4*i,off)
    for i,idx in enumerate(types):struct.pack_into('<I',data,144+4*i,idx)
    struct.pack_into('<III',data,160,6,2,0);struct.pack_into('<III',data,172,7,2,params)
    struct.pack_into('<HHI',data,184,0,0,4);struct.pack_into('<HHI',data,192,1,1,5)
    struct.pack_into('<8I',data,200,0,1,0xffffffff,0,0xffffffff,0,classdata,0)
    return reseal(data)


def reseal(data):
    data=bytearray(data);data[12:32]=hashlib.sha1(data[32:]).digest();struct.pack_into('<I',data,8,zlib.adler32(data[12:])&0xffffffff);return bytes(data)


def archive(entries, compressed=False):
    buf=io.BytesIO()
    with zipfile.ZipFile(buf,'w',compression=zipfile.ZIP_DEFLATED if compressed else zipfile.ZIP_STORED) as z:
        for name,data in entries:z.writestr(name,data)
    return buf.getvalue()


class AndroidTests(unittest.TestCase):
    def setUp(self):self.temp=tempfile.TemporaryDirectory();self.path=Path(self.temp.name)/'input'
    def tearDown(self):self.temp.cleanup()
    def run_action(self,data,action='artifact_discovery',**kwargs):
        self.path.write_bytes(data);return w.investigate(dict(action=action,target=str(self.path),**kwargs))
    def test_generated_source_parity(self):
        src=(HERE.parent/'src/extensions/tools/executors/android-investigation-worker.ts').read_text()
        embedded=json.loads(src.split('export const ANDROID_INVESTIGATION_WORKER = ',1)[1].strip().removesuffix(';'))
        self.assertEqual(embedded,(HERE/'android-investigation-worker.py').read_text())
    def test_integrity_and_native_lookup(self):
        result=self.run_action(dex_fixture(),'android_method',options={'method':{'class_descriptor':'LFixture;','name':'native_work','descriptor':'()V'}})
        e=result['evidence'];self.assertEqual(e['selectedMethods'][0]['native'],True)
        self.assertEqual(e['selectedMethods'][0]['codeOffset'],0)
        self.assertFalse(e['relationships'][0]['verifiedBinding'])
        self.assertEqual(e['relationships'][0]['shortName'],'Java_Fixture_native_1work')
    def test_exact_code_range_and_byte_fingerprint(self):
        data=dex_fixture(True)
        result=self.run_action(data,'android_method',options={'method':{'class_descriptor':'LFixture;','name':'native_work','descriptor':'()V'}})
        method=result['evidence']['selectedMethods'][0]
        self.assertFalse(method['native']);self.assertEqual(method['instructionBytes'],2)
        self.assertEqual(data[method['instructionOffset']:method['instructionOffset']+2],b'\x0e\x00')
        self.assertEqual(method['byteFingerprint'],hashlib.sha256(b'\x0e\x00').hexdigest())
    def test_resealed_code_range_rejected(self):
        data=bytearray(dex_fixture(True));_,methods=w.dex_metadata(data,200);code=methods[0]['codeOffset']
        struct.pack_into('<I',data,code+12,100000)
        self.assertIn('code item bounds',self.run_action(reseal(data))['evidence']['artifacts'][0]['reason'])
    def test_loader_pool_reference_not_execution(self):
        result=self.run_action(dex_fixture(),'android_relationships')
        refs=result['evidence']['artifacts'][0]['dex']['loaderReferences']
        self.assertEqual(refs[0]['name'],'loadLibrary');self.assertFalse(refs[0]['defined'])
    def test_embedded_hidden_name(self):
        result=self.run_action(archive([('assets/payload.bin',b'junk'+dex_fixture()+b'tail')]))
        dex=next(r for r in result['evidence']['artifacts'] if r['format']=='dex')
        self.assertEqual(dex['offsetInParent'],4);self.assertEqual(dex['origin'],'carved')
        self.assertEqual(dex['validation'],'integrity-and-bounded-structure')
    def test_compressed_nested(self):
        result=self.run_action(zlib.compress(archive([('hidden',dex_fixture())])))
        self.assertTrue(any(r['format']=='dex' for r in result['evidence']['artifacts']))
    def test_tampered_checksum_is_candidate(self):
        data=bytearray(dex_fixture());data[-1]^=1
        r=self.run_action(data)['evidence']['artifacts'][0]
        self.assertIn('rejected',r['validation']);self.assertIn('Adler',r['reason'])
    def test_resealed_pool_out_of_bounds(self):
        data=bytearray(dex_fixture());struct.pack_into('<I',data,60,len(data)+8)
        r=self.run_action(reseal(data))['evidence']['artifacts'][0]
        self.assertIn('pool bounds',r['reason'])
    def test_map_duplicates_rejected(self):
        data=bytearray(dex_fixture());off=w.u32(data,52);struct.pack_into('<H',data,off+16,0)
        self.assertIn('map entries',self.run_action(reseal(data))['evidence']['artifacts'][0]['reason'])
    def test_traversal_no_extraction(self):
        result=self.run_action(archive([('../escape',dex_fixture())]))
        self.assertEqual(len(result['evidence']['artifacts']),1);self.assertEqual(result['status'],'partial')
        self.assertFalse((self.path.parent.parent/'escape').exists())
    def test_symlink_member_rejected(self):
        info=zipfile.ZipInfo('link');info.external_attr=0o120777<<16
        result=self.run_action(archive([(info,b'target')]))
        self.assertIn('unsafe',result['evidence']['artifacts'][0]['reason'])
    def test_duplicate_member_rejected(self):
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter('ignore');data=archive([('same',b'1'),('same',b'2')])
        self.assertEqual(len(self.run_action(data)['evidence']['artifacts']),1)
    def test_zip_expansion_limit(self):
        result=self.run_action(archive([('bomb',b'0'*200000)],True))
        self.assertTrue(result['evidence']['coverage']['truncated']);self.assertEqual(len(result['evidence']['artifacts']),1)
    def test_trailing_compression_rejected(self):
        r=self.run_action(zlib.compress(dex_fixture())+b'tail')['evidence']['artifacts'][0]
        self.assertEqual(r['validation'],'compression-rejected')
    def test_crc_error_retains_partial_container(self):
        data=bytearray(archive([('payload',b'unique-payload')]))
        pos=data.find(b'unique-payload');data[pos]^=1
        result=self.run_action(data)
        self.assertEqual(result['status'],'partial');self.assertIn('CRC',result['evidence']['artifacts'][0]['reason'])
    def test_encrypted_zip_rejected(self):
        data=bytearray(archive([('payload',b'x')]))
        local=data.find(b'PK\x03\x04');central=data.find(b'PK\x01\x02')
        struct.pack_into('<H',data,local+6,1);struct.pack_into('<H',data,central+8,1)
        self.assertIn('encrypted',self.run_action(data)['evidence']['artifacts'][0]['reason'])
    def test_unsupported_compact_dex_is_candidate(self):
        record=self.run_action(b'cdex001\0'+b'\0'*120)['evidence']['artifacts'][0]
        self.assertIn('unsupported',record['validation']);self.assertNotIn('dex',record)
    def test_depth_limit_explicit(self):
        result=self.run_action(archive([('child',dex_fixture())]),options={'discovery':{'max_depth':0}})
        self.assertTrue(result['evidence']['coverage']['truncated'])
    def test_aggregate_method_budget_keeps_partial_evidence(self):
        from unittest.mock import patch
        with patch.object(w,'MAX_TOTAL_METHODS',2):
            result=self.run_action(archive([('a',dex_fixture()),('b',dex_fixture())]))
        self.assertTrue(result['evidence']['coverage']['truncated'])
        self.assertEqual(result['evidence']['coverage']['parsedMethodCount'],2)
        self.assertIn('aggregate method budget',result['evidence']['artifacts'][-1]['reason'])
    def test_artifact_limit_explicit(self):
        result=self.run_action(archive([('a',dex_fixture()),('b',dex_fixture())]),options={'discovery':{'max_artifacts':2}})
        self.assertEqual(len(result['evidence']['artifacts']),2);self.assertTrue(result['evidence']['coverage']['truncated'])
    def test_ambiguous_multidex_selection(self):
        result=self.run_action(archive([('a',dex_fixture()),('b',dex_fixture())]),'android_method',options={'method':{'class_descriptor':'LFixture;','name':'native_work','descriptor':'()V'}})
        self.assertTrue(result['evidence']['ambiguousAcrossArtifacts'])
        self.assertNotEqual(result['evidence']['selectedMethods'][0]['id'],result['evidence']['selectedMethods'][1]['id'])
    def test_missing_method_is_not_success(self):
        result=self.run_action(dex_fixture(),'android_method',options={'method':{'class_descriptor':'LNope;','name':'x','descriptor':'()V'}})
        self.assertEqual(result['status'],'partial');self.assertEqual(result['evidence']['selectionStatus'],'not-found-in-covered-artifacts')
    def test_unknown_blob_entropy_not_encryption(self):
        r=self.run_action(bytes(range(256)))['evidence']['artifacts'][0]
        self.assertEqual(r['sampleEntropy'],8);self.assertIn('Not evidence of encryption',r['entropyInterpretation'])
    def test_elf_is_signature_candidate(self):
        result=self.run_action(b'\x7fELF' + b'\0'*128)
        self.assertEqual(result['status'],'partial');self.assertEqual(result['evidence']['artifacts'][0]['validation'],'signature-only-candidate')
    def test_jni_utf16_mangling(self):
        self.assertEqual(w.jni_escape('a_b/[;é'),'a_1b__3_2_000e9')
    def test_uleb_overflow(self):
        with self.assertRaises(ValueError):w.uleb(b'\xff'*5,0)
    def test_modified_utf8_null(self):
        self.assertEqual(w.dex_string(b'\x01\xc0\x80\0',0),'\0')
    def test_method_list_limit_recorded(self):
        result=self.run_action(dex_fixture(),limit=1)
        self.assertEqual(result['status'],'partial');self.assertTrue(result['evidence']['artifacts'][0]['dex']['methodsTruncated'])
    def test_signature_with_invalid_declared_size_not_valid(self):
        result=self.run_action(b'prefix'+b'dex\n035\0'+b'\0'*112)
        self.assertEqual(len(result['evidence']['artifacts']),1);self.assertTrue(result['evidence']['warnings'])

if __name__=='__main__':unittest.main()
