import hashlib
import importlib.util
import io
import json
import struct
import tempfile
import unittest
import zipfile
import zlib
import xml.etree.ElementTree as ET
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


def calls_fixture(root_code=b'\x71\x00\x01\x00\x00\x00\x0e\x00'):
    """Owned two-method DEX: root invokes caller; caller invokes root. Never executed."""
    strings=['LCalls;','V','root','caller']
    data=bytearray(196);string_offsets=[]
    for value in strings:
        string_offsets.append(len(data));data+=bytes([len(value)])+value.encode()+b'\0'
    while len(data)%4:data+=b'\0'
    code_offsets=[]
    for body in [root_code,b'\x71\x00\x00\x00\x00\x00\x0e\x00']:
        assert len(body)%2==0
        code_offsets.append(len(data));data+=struct.pack('<HHHHII',0,0,0,0,0,len(body)//2)+body
        while len(data)%4:data+=b'\0'
    classdata=len(data);data+=b'\0\0\x02\0'
    for delta,offset in zip([0,1],code_offsets):
        data+=bytes([delta,9]);value=offset
        while value>=128:data+=bytes([(value&127)|128]);value>>=7
        data+=bytes([value])
    while len(data)%4:data+=b'\0'
    mapoff=len(data)
    entries=[(0,1,0),(1,4,112),(2,2,128),(3,1,136),(5,2,148),(6,1,164),(0x2002,4,196),(0x2001,2,code_offsets[0]),(0x2000,1,classdata),(0x1000,1,mapoff)]
    data+=struct.pack('<I',len(entries))
    for kind,count,offset in entries:data+=struct.pack('<HHII',kind,0,count,offset)
    data[:8]=b'dex\n035\0'
    struct.pack_into('<20I',data,32,len(data),112,0x12345678,0,0,mapoff,4,112,2,128,1,136,0,0,2,148,1,164,len(data)-196,196)
    for i,offset in enumerate(string_offsets):struct.pack_into('<I',data,112+4*i,offset)
    struct.pack_into('<II',data,128,0,1);struct.pack_into('<III',data,136,1,1,0)
    struct.pack_into('<HHI',data,148,0,0,2);struct.pack_into('<HHI',data,156,0,0,3)
    struct.pack_into('<8I',data,164,0,1,0xffffffff,0,0xffffffff,0,classdata,0)
    return reseal(data)


def archive(entries, compressed=False):
    buf=io.BytesIO()
    with zipfile.ZipFile(buf,'w',compression=zipfile.ZIP_DEFLATED if compressed else zipfile.ZIP_STORED) as z:
        for name,data in entries:
            # Preserve malicious bytes rather than ZipInfo's host-dependent
            # separator/NUL normalization before archive serialization.
            if isinstance(name,zipfile.ZipInfo):
                z.writestr(name,data);continue
            entry=zipfile.ZipInfo('fixture')
            entry.filename=name;entry.orig_filename=name;entry.create_system=3
            entry.compress_type=zipfile.ZIP_DEFLATED if compressed else zipfile.ZIP_STORED
            z.writestr(entry,data)
    return buf.getvalue()


def elf_fixture(machine=62, code=b"\x90\xc3", entries=None):
    base=0x400000
    text=192
    data=bytearray(text)+code
    entries=entries or [('Java_Fixture_native_1work',0,len(code))]
    names=b'\0';symbol_rows=[]
    for name,offset,size in entries:
        symbol_rows.append((len(names),offset,size));names+=name.encode()+b'\0'
    strings=len(data);data+=names
    while len(data)%8:data+=b'\0'
    symbols=len(data);data+=bytes(24)
    for name,offset,size in symbol_rows:data+=struct.pack('<IBBHQQ',name,0x12,0,1,base+text+offset,size)
    hashes=len(data);data+=struct.pack('<III',1,len(entries)+1,1)+b''.join(struct.pack('<I',i+1 if 0<i<len(entries) else 0) for i in range(len(entries)+1))
    while len(data)%8:data+=b'\0'
    dynamic=len(data)
    for tag,value in [(5,base+strings),(10,len(names)),(6,base+symbols),(11,24),(4,base+hashes),(0,0)]:data+=struct.pack('<QQ',tag,value)
    shnames=b'\0.text\0.dynstr\0.dynsym\0.hash\0.dynamic\0.shstrtab\0'
    stringtable=len(data);data+=shnames
    while len(data)%8:data+=b'\0'
    sectionoff=len(data);data+=bytes(64)
    for name,kind,flags,address,offset,size,link,align,entsize in [(1,1,6,base+text,text,len(code),0,16,0),(7,3,2,base+strings,strings,len(names),0,1,0),(15,11,2,base+symbols,symbols,24*(len(entries)+1),2,8,24),(23,5,2,base+hashes,hashes,12+4*(len(entries)+1),3,4,4),(29,6,3,base+dynamic,dynamic,96,2,8,16),(38,3,0,0,stringtable,len(shnames),0,1,0)]:
        data+=struct.pack('<IIQQQQIIQQ',name,kind,flags,address,offset,size,link,0,align,entsize)
    data[:16]=b'\x7fELF\x02\x01\x01'+bytes(9)
    struct.pack_into('<HHIQQQIHHHHHH',data,16,3,machine,1,0,64,sectionoff,0,64,56,2,64,7,6)
    struct.pack_into('<IIQQQQQQ',data,64,1,5,0,base,base,len(data),len(data),4096)
    struct.pack_into('<IIQQQQQQ',data,120,2,4,dynamic,base+dynamic,base+dynamic,96,96,8)
    return bytes(data)


class AndroidTests(unittest.TestCase):
    def setUp(self):self.temp=tempfile.TemporaryDirectory();self.path=Path(self.temp.name)/'input'
    def tearDown(self):self.temp.cleanup()
    def run_action(self,data,action='artifact_discovery',**kwargs):
        self.path.write_bytes(data);return w.investigate(dict(action=action,target=str(self.path),**kwargs))
    def entrypoint_fixture(self,with_code=True):
        raw=dex_fixture(with_code).replace(b'LFixture;',b'Lapp/Xxx;').replace(b'native_work',b'onTerminate')
        return reseal(raw)
    def manifest(self,body='<application android:name=".Xxx"/>'):
        return ('<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="app">'+body+'</manifest>').encode()
    def entrypoints(self,entries,**options):
        self.path.write_bytes(archive(entries))
        return w.android_entrypoints(dict(action='android_entrypoints',target=str(self.path),options={'entrypoints':options}))
    def resources(self,left,right,limit=200):
        self.path.write_bytes(archive(left));other=self.path.parent/'right.apk';other.write_bytes(archive(right))
        return w.android_resources(dict(action='android_resources',target=str(self.path),compare_target=str(other),limit=limit))
    def test_entrypoints_exact_defined_callback_and_owned_fixture(self):
        manifest=self.manifest();dex=self.entrypoint_fixture()
        r=self.entrypoints([('AndroidManifest.xml',manifest),('classes.dex',dex)])
        e=r['evidence'];self.assertEqual(r['status'],'partial');self.assertEqual(e['candidateCount'],1)
        c=e['candidates'][0];self.assertEqual((c['declaringClass'],c['name'],c['descriptor']),('Lapp/Xxx;','onTerminate','()V'))
        self.assertEqual(c['artifactSha256'],hashlib.sha256(dex).hexdigest());self.assertFalse(c['dispatchVerified']);self.assertFalse(c['executionObserved'])
        self.assertFalse(c['native']);self.assertTrue(c['byteFingerprint']);self.assertEqual(e['components'][0]['searchStopped'],'hierarchy-root-reached')
        import base64
        fixture=json.loads((HERE/'owned-android-entrypoints-fixture.json').read_text());blob=base64.b64decode(fixture['base64'])
        self.assertEqual(hashlib.sha256(blob).hexdigest(),fixture['sha256'])
        self.path.write_bytes(blob);actual=w.android_entrypoints({'target':str(self.path),'action':'android_entrypoints'})
        self.assertEqual(actual['evidence']['candidateCount'],1)
    def test_entrypoints_inheritance_aliases_exact_signatures_and_no_static_override(self):
        root,_enc,_nodes=w.workflow_xml(self.manifest('<application><activity android:name=".Xxx"/><activity-alias android:name=".Alias" android:targetActivity=".Xxx" android:exported="true"/></application>'))
        _pkg,components=w.manifest_components(root)
        classes=[{'descriptor':'Lapp/Xxx;','superclass':'Lapp/Base;','artifactId':'a','artifactSha256':'a'*64}, {'descriptor':'Lapp/Base;','superclass':None,'artifactId':'b','artifactSha256':'b'*64}]
        methods=[{'artifactId':'a','classDescriptor':'Lapp/Xxx;','name':'onStart','descriptor':'()V','defined':True,'accessFlags':9,'methodIndex':0},
                 {'artifactId':'a','classDescriptor':'Lapp/Xxx;','name':'onStart','descriptor':'(I)V','defined':True,'accessFlags':1,'methodIndex':1},
                 {'artifactId':'b','classDescriptor':'Lapp/Base;','name':'onStart','descriptor':'()V','defined':True,'accessFlags':1,'methodIndex':2}]
        r=w.entrypoint_candidates(components,classes,methods,8,64,200)
        self.assertEqual(r['candidateCount'],2);self.assertTrue(all(c['inheritedDepth']==1 for c in r['candidates']))
        self.assertEqual(r['components'][1]['kind'],'activity-alias');self.assertEqual(r['components'][1]['exportedDeclared'],'true')
    def test_entrypoints_duplicate_multidex_class_is_never_silently_selected(self):
        dex=self.entrypoint_fixture();r=self.entrypoints([('AndroidManifest.xml',self.manifest()),('classes.dex',dex),('classes2.dex',dex)])
        self.assertEqual(r['evidence']['candidateCount'],0);self.assertEqual(r['evidence']['components'][0]['searchStopped'],'ambiguous-class')
        r=self.entrypoints([('AndroidManifest.xml',self.manifest()),('classes.dex',dex),('classes2.dex',dex)],max_dex_files=1)
        self.assertTrue(r['evidence']['coverage']['dexTruncated']);self.assertFalse(r['evidence']['dispatchVerified'])
    def test_entrypoints_nondefinitions_invalid_dex_unknown_names_disabled_declarations(self):
        r=self.entrypoints([('AndroidManifest.xml',self.manifest('<application android:enabled="false" android:name="@string/app"><receiver android:name=".Missing" android:enabled="false"/></application>')),('classes.dex',b'dex\n035\0broken')])
        e=r['evidence'];self.assertEqual(e['candidateCount'],0);self.assertEqual(len(e['rejectedDex']),1)
        self.assertIsNone(e['components'][0]['classDescriptor']);self.assertEqual(e['components'][1]['enabledDeclared'],'false')
        self.assertEqual(e['components'][1]['applicationEnabledDeclared'],'false')
    def test_entrypoints_budget_cycle_and_unrelated_options_fail_closed(self):
        root,*_=w.workflow_xml(self.manifest());_,components=w.manifest_components(root)
        classes=[{'descriptor':'Lapp/Xxx;','superclass':'Lapp/Xxx;','artifactId':'a','artifactSha256':'a'*64}]
        r=w.entrypoint_candidates(components,classes,[],8,1,1);self.assertEqual(r['components'][0]['searchStopped'],'hierarchy-cycle')
        r=w.entrypoint_candidates(components,classes,[],0,1,1);self.assertEqual(r['components'][0]['searchStopped'],'max-depth')
        for opts in [{'max_depth':-1},{'max_depth':True},{'max_components':129},{'max_dex_files':0},{'unknown':1}]:
            with self.assertRaises(ValueError):self.entrypoints([('AndroidManifest.xml',self.manifest())],**opts)
        with self.assertRaises(ValueError):w.android_entrypoints({'options':{'method':{}},'target':str(self.path)})
    def test_entrypoints_component_and_candidate_details_have_full_counts(self):
        dex=self.entrypoint_fixture();body='<application android:name=".Xxx">'+''.join('<service android:name=".Missing%d"/>'%i for i in range(3))+'</application>'
        r=self.entrypoints([('AndroidManifest.xml',self.manifest(body)),('classes.dex',dex)],max_components=1)
        e=r['evidence'];self.assertTrue(e['componentsTruncated']);self.assertEqual(e['componentCount'],4);self.assertEqual(len(e['components']),1)
    def test_android_xml_dtd_entities_utf16_invalid_and_depth_are_rejected(self):
        for data in [b'<!DOCTYPE a [<!ENTITY x "owned">]><a>&x;</a>',b'<a>\x00</a>','<a/>'.encode('utf-16'),b'<a>',b'<a>'*66+b'</a>'*66,b'<a/>'*2]:
            with self.assertRaises((ValueError,ET.ParseError,UnicodeError)):w.workflow_xml(data)
        with self.assertRaises(ValueError):w.workflow_xml(b'x'*(1024*1024+1))
    def test_android_resources_reads_real_sha256_and_all_categories_with_xml_structure(self):
        a=b'<resources xmlns:x="urn:x" x:a="1" b="2"><string name="x">A</string></resources>'
        b=b'<resources b="2" xmlns:y="urn:x" y:a="1"><string name="x">A</string></resources>'
        left=[('AndroidManifest.xml',self.manifest()),('res/values/strings.xml',a),('assets/x',b'old'),('classes.dex',b'old'),('lib/x/x.so',b'old'),('removed',b'x')]
        right=[('AndroidManifest.xml',self.manifest('<application/>')),('res/values/strings.xml',b),('assets/x',b'new'),('classes.dex',b'new'),('lib/x/x.so',b'new'),('added',b'x')]
        r=self.resources(left,right);e=r['evidence'];self.assertEqual(r['status'],'partial');self.assertEqual(e['changedFiles'],7)
        self.assertEqual(e['categoryCounts'],{'manifest':1,'resources':1,'assets':1,'dex':1,'native':1,'other':2})
        row=next(c for c in e['changes'] if c['category']=='resources');self.assertTrue(row['parsedXmlStructureEqual']);self.assertNotEqual(row['before']['sha256'],row['after']['sha256'])
        self.assertEqual(row['before']['sha256'],hashlib.sha256(a).hexdigest());self.assertFalse(e['observedExecution']);self.assertFalse(e['published'])
    def test_android_resources_equal_bytes_and_detail_budget(self):
        pairs=[('assets/a',b'a'),('assets/b',b'b')];self.assertTrue(self.resources(pairs,pairs)['evidence']['identicalEntryBytes'])
        e=self.resources(pairs,[('assets/a',b'c'),('assets/b',b'd')],1)['evidence']
        self.assertEqual(e['changedFiles'],2);self.assertEqual(len(e['changes']),1);self.assertTrue(e['changesTruncated']);self.assertEqual(len(e['changeSetSha256']),64)
    def test_android_resources_xml_unavailable_does_not_claim_equal_or_ignore_bytes(self):
        e=self.resources([('res/a.xml',b'<a>')],[('res/a.xml',b'<a/>')])['evidence'];row=e['changes'][0]
        self.assertEqual(row['before']['xmlStructure']['status'],'unavailable');self.assertNotIn('parsedXmlStructureEqual',row)
        self.assertNotEqual(w.xml_structure_hash(b'<a> A </a>')['sha256'],w.xml_structure_hash(b'<a>A</a>')['sha256'])
    def test_android_zip_duplicate_case_alias_traversal_and_special_entries_rejected(self):
        for pairs in [[('a',b'a'),('A',b'b')],[('../a',b'a')],[('a\\b',b'a')],[('a\x00b',b'a')]]:
            with self.assertRaises(ValueError):self.resources(pairs,[])
        buf=io.BytesIO()
        with zipfile.ZipFile(buf,'w') as z:
            e=zipfile.ZipInfo('link');e.external_attr=0o120777<<16;z.writestr(e,'target')
        self.path.write_bytes(buf.getvalue())
        with self.assertRaises(ValueError):w.workflow_zip(str(self.path),[0])
    def test_android_zip_central_directory_forged_count_and_trailing_payload_rejected(self):
        blob=bytearray(archive([('a',b'a')]));end=blob.rfind(b'PK\x05\x06');struct.pack_into('<HH',blob,end+8,0,0)
        for data in [bytes(blob),archive([('a',b'a')])+b'payload',b'PK\x03\x04invalid']:
            self.path.write_bytes(data)
            with self.assertRaises(ValueError):w.workflow_zip(str(self.path),[0])
    def test_android_zip_expansion_and_cross_archive_aggregate_budget_fail_closed(self):
        self.path.write_bytes(archive([('a',b'a'*100000)],True))
        data,z,entries=w.workflow_zip(str(self.path),[0])
        with z:
            with self.assertRaises(ValueError):w.workflow_member(z,entries[0],[0])
        self.path.write_bytes(archive([('a',b'x')]))
        data,z,entries=w.workflow_zip(str(self.path),[0])
        with z:
            with self.assertRaises(ValueError):w.workflow_member(z,entries[0],[w.MAX_WORK])
    def test_generated_source_parity(self):
        src=(HERE.parent/'src/extensions/tools/executors/android-investigation-worker.ts').read_text()
        embedded=json.loads(src.split('export const ANDROID_INVESTIGATION_WORKER = ',1)[1].strip().removesuffix(';'))
        self.assertEqual(embedded,(HERE/'android-investigation-worker.py').read_text())
    def identify(self,data,**budgets):
        return self.run_action(data,options={'discovery':{'identify_formats':True,**budgets}})
    def test_identify_owned_nested_fixture_hashes_origins_and_unknown(self):
        import base64
        fixture=json.loads((HERE/'owned-artifact-discovery-fixture.json').read_text())
        data=base64.b64decode(fixture['base64']);r=self.identify(data);e=r['evidence']
        self.assertEqual(r['input']['sha256'],fixture['sha256']);self.assertEqual(r['status'],'partial')
        self.assertEqual([a['format'] for a in e['artifacts']],['zip','gzip','dex','opaque','opaque'])
        self.assertEqual(e['identification']['ambiguousCount'],1);self.assertEqual(e['identification']['unknownCount'],1)
        self.assertFalse(e['identification']['observedExecution']);self.assertEqual(e['artifacts'][1]['logicalPath'],'payload.exe')
        self.assertEqual(e['artifacts'][2]['origin'],'gzip-expansion')
        for a in e['artifacts'][1:]:self.assertIn(a['parentId'],[n['id'] for n in e['artifacts']])
        self.assertEqual(len(list(self.path.parent.iterdir())),1);self.assertEqual(self.path.read_bytes(),data)
    def test_identify_mz_prefixed_zip_preserves_conflicting_candidates(self):
        r=self.identify(b'MZ'+b'\0'*62+archive([('owned',dex_fixture())]));a=r['evidence']['artifacts'][0]
        self.assertEqual(a['format'],'zip');self.assertTrue(a['identification']['ambiguous'])
        self.assertEqual([c['format'] for c in a['identification']['candidates']],['pe','zip'])
        self.assertEqual(a['identification']['status'],'ambiguous');self.assertEqual(r['status'],'partial')
        self.assertTrue(any(a['format']=='dex' for a in r['evidence']['artifacts']))
    def test_identify_signatures_unknown_and_empty_never_completed(self):
        for data in [b'',b'unknown',b'MZ',b'\x00asm',b'\xcf\xfa\xed\xfe',b'\xca\xfe\xba\xbe']:
            with self.subTest(data=data):self.assertEqual(self.identify(data)['status'],'partial')
        self.assertEqual(self.identify(b'\xca\xfe\xba\xbe')['evidence']['artifacts'][0]['identification']['status'],'ambiguous')
    def test_identify_valid_dex_has_bounded_validation_not_runtime_claim(self):
        r=self.identify(dex_fixture())
        self.assertEqual(r['status'],'completed');self.assertEqual(r['evidence']['artifacts'][0]['identification']['status'],'bounded-validated')
        self.assertFalse(r['evidence']['identification']['observedExecution'])
    def test_identify_limits_and_rejection_never_completed(self):
        data=archive([('owned',dex_fixture())])
        for budgets in [{'max_depth':0},{'max_artifacts':1}]:
            r=self.identify(data,**budgets);self.assertEqual(r['status'],'partial');self.assertEqual(len(r['evidence']['artifacts']),1)
        self.assertEqual(self.identify(archive([('../escape',b'x')]))['status'],'partial')
        self.assertEqual(self.identify(b'PK\x03\x04bad')['status'],'partial')
    def jni_trace(self,data,**overrides):
        options={'method':{'class_descriptor':'LFixture;','name':'native_work','descriptor':'()V'},'jni_trace':{'max_candidates':16,'native_calls':{'max_depth':2,'max_functions':3,'max_edges':4,'max_total_bytes':32}}}
        options.update(overrides)
        return self.run_action(data,'android_relationships',options=options)
    def test_fresh_jni_missing_and_non_native_selection_no_traversal(self):
        for data in [dex_fixture(),dex_fixture(True),archive([('opaque',b'x')])]:
            r=self.jni_trace(data);trace=r['evidence']['crossLanguageTrace']
            self.assertEqual(r['status'],'partial');self.assertFalse(trace['bindingVerified']);self.assertFalse(trace['observedExecution'])
            self.assertEqual(trace['nativeTraversal']['status'],'not-started')
    def test_fresh_jni_real_export_to_bounded_native_cycle(self):
        try:import lief,capstone
        except ImportError:self.skipTest('optional LIEF and Capstone unavailable')
        import base64
        fixture=json.loads((HERE/'owned-jni-cross-language-fixture.json').read_text());data=base64.b64decode(fixture['base64'])
        r=self.jni_trace(data);trace=r['evidence']['crossLanguageTrace'];graph=trace['nativeTraversal']['callGraph']
        self.assertEqual(r['input']['sha256'],fixture['sha256']);self.assertEqual(trace['nativeTraversal']['nativeArtifactSha256'],fixture['nativeSha256'])
        self.assertEqual(trace['selectedMethodCount'],1);self.assertEqual(trace['candidateCount'],1)
        self.assertEqual([n['name'] for n in graph['nodes']],['Java_Fixture_native_1work','owned_child','owned_leaf'])
        self.assertEqual(graph['edges'][-1]['resolution'],'already-scheduled-or-visited');self.assertFalse(graph['observedExecution'])
        self.assertEqual(r['status'],'partial');self.assertEqual(trace['registrationStatus'],'unresolved-not-observed');self.assertEqual(self.path.read_bytes(),data)
    def test_fresh_jni_multidex_ambiguity_does_not_follow_native(self):
        try:import lief
        except ImportError:self.skipTest('optional LIEF unavailable')
        r=self.jni_trace(archive([('classes.dex',dex_fixture()),('classes2.dex',dex_fixture()),('lib/owned.so',elf_fixture())]))
        t=r['evidence']['crossLanguageTrace'];self.assertEqual(t['selectedMethodCount'],2);self.assertEqual(t['nativeTraversal']['status'],'not-started')
    def test_fresh_jni_abi_selection_and_depth_budget(self):
        try:import lief,capstone
        except ImportError:self.skipTest('optional LIEF and Capstone unavailable')
        data=archive([('classes.dex',dex_fixture()),('lib/a/owned.so',elf_fixture()),('lib/b/owned.so',elf_fixture())])
        ambiguous=self.jni_trace(data)['evidence']['crossLanguageTrace'];self.assertEqual(ambiguous['candidateCount'],2);self.assertEqual(ambiguous['nativeTraversal']['status'],'not-started')
        selected=self.jni_trace(data,jni_trace={'native_artifact':'lib/a/owned.so','max_candidates':1,'native_calls':{'max_depth':0}})['evidence']['crossLanguageTrace']
        self.assertEqual(selected['candidateCount'],1);self.assertEqual(len(selected['nativeTraversal']['callGraph']['nodes']),1)
        missing=self.jni_trace(data,jni_trace={'native_artifact':'lib/missing.so'})['evidence']['crossLanguageTrace'];self.assertEqual(missing['candidateCount'],0);self.assertEqual(missing['nativeTraversal']['status'],'not-started')
    def test_fresh_jni_candidate_cap_explicit(self):
        try:import lief
        except ImportError:self.skipTest('optional LIEF unavailable')
        r=self.jni_trace(archive([('classes.dex',dex_fixture()),('lib/a.so',elf_fixture()),('lib/b.so',elf_fixture())]),jni_trace={'max_candidates':1})
        t=r['evidence']['crossLanguageTrace'];self.assertEqual(len(t['candidateExports']),1);self.assertTrue(t['candidatesTruncated']);self.assertEqual(t['nativeTraversal']['status'],'not-started')
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


    @unittest.skipUnless(importlib.util.find_spec('lief') and importlib.util.find_spec('capstone'),'optional real engines not configured')
    def test_exact_native_entry_maps_virtual_to_file(self):
        self.path.write_bytes(elf_fixture())
        result=w.native_selection({'target':str(self.path),'options':{'function':{'address':'0x4000c0'}}})
        method=result['evidence']['selectedFunctions'][0]
        self.assertEqual(method['fileOffset'],192);self.assertEqual([i['mnemonic'] for i in method['disassembly']['instructions']],['nop','ret'])
        self.assertEqual(result['status'],'completed')
    @unittest.skipUnless(importlib.util.find_spec('lief') and importlib.util.find_spec('capstone'),'optional real engines not configured')
    def test_arm64_native_entry(self):
        self.path.write_bytes(elf_fixture(183,bytes.fromhex('c0035fd6')))
        result=w.native_selection({'target':str(self.path),'options':{'function':{'address':'0x4000c0'}}})
        self.assertEqual(result['evidence']['selectedFunctions'][0]['architecture'],'arm64')
        self.assertEqual(result['evidence']['selectedFunctions'][0]['disassembly']['instructions'][0]['mnemonic'],'ret')
    @unittest.skipUnless(importlib.util.find_spec('lief') and importlib.util.find_spec('capstone'),'optional real engines not configured')
    def test_partial_native_range_explicit(self):
        self.path.write_bytes(elf_fixture());r=w.native_selection({'target':str(self.path),'options':{'function':{'symbol':'Java_Fixture_native_1work','max_bytes':1}}})
        self.assertEqual(r['status'],'partial');self.assertEqual(r['evidence']['selectedFunctions'][0]['disassembly']['decodedBytes'],1)
    @unittest.skipUnless(importlib.util.find_spec('lief'),'optional LIEF not configured')
    def test_jni_export_matches_remain_candidates(self):
        result=self.run_action(archive([('classes.dex',dex_fixture()),('lib/x86_64/a.so',elf_fixture())]),'android_relationships')
        matches=[r for r in result['evidence']['relationships'] if r['kind']=='jni-export-match-candidate']
        self.assertEqual(result['evidence']['relationshipCount'],len(result['evidence']['relationships']));self.assertEqual(result['evidence']['exportMatchCount'],1)
        self.assertEqual(len(matches),1);self.assertFalse(matches[0]['verifiedBinding']);self.assertEqual(matches[0]['confidence'],'static-export-name-match')
    @unittest.skipUnless(importlib.util.find_spec('lief'),'optional LIEF not configured')
    def test_native_budget_and_invalid_extent_do_not_execute(self):
        data=bytearray(elf_fixture());struct.pack_into('<Q',data,64+32,len(data)+100)
        with self.assertRaises(ValueError):w.native_metadata(bytes(data),'owned',20)
    def test_owned_method_call_fixture_matches_generator(self):
        import base64
        f=json.loads((HERE/'owned-android-method-calls-fixture.json').read_text())
        data=calls_fixture();self.assertEqual(base64.b64decode(f['base64']),data)
        self.assertEqual(f['sha256'],hashlib.sha256(data).hexdigest())
        ambiguous=base64.b64decode(f['ambiguousBase64'])
        self.assertEqual(f['ambiguousSha256'],hashlib.sha256(ambiguous).hexdigest())
        with zipfile.ZipFile(io.BytesIO(ambiguous)) as z:
            self.assertEqual(z.namelist(),['classes.dex','classes2.dex'])
            self.assertEqual(z.read('classes.dex'),data);self.assertEqual(z.read('classes2.dex'),data)

    def test_method_calls_missing_engine_is_explicit_and_partial(self):
        from unittest.mock import patch
        with patch.object(w, 'android_method_calls', side_effect=ImportError('owned missing engine')):
            result=self.run_action(calls_fixture(),'android_method',options={'method':{'class_descriptor':'LCalls;','name':'root','descriptor':'()V'}})
        self.assertEqual(result['status'],'partial')
        self.assertEqual(result['evidence']['methodCalls']['status'],'blocked')
        self.assertFalse(result['evidence']['methodCalls']['observedExecution'])

    @unittest.skipUnless(importlib.util.find_spec('androguard'),'optional Androguard not configured')
    def test_bounded_real_method_call_references_keep_exact_origin_and_offsets(self):
        data=calls_fixture();self.path.write_bytes(data)
        result=self.run_action(data,'android_method',options={'method':{'class_descriptor':'LCalls;','name':'root','descriptor':'()V'}})
        calls=result['evidence']['methodCalls'];self.assertEqual(calls['selectionStatus'],'defined')
        self.assertEqual(calls['referenceCount'],2);self.assertEqual(len(calls['references']),2)
        self.assertEqual({r['relativeToSelection'] for r in calls['references']},{'caller','callee'})
        self.assertEqual(calls['coverage']['methods'],2);self.assertEqual(calls['coverage']['instructions'],4)
        for row in calls['references']:
            self.assertEqual(row['bytecodeOffset'],0);self.assertEqual(row['artifactSha256'],hashlib.sha256(data).hexdigest())
            self.assertEqual(row['opcode'],'invoke-static');self.assertEqual(row['definitionCandidateCount'],1)
            self.assertFalse(row['dispatchVerified']);self.assertFalse(row['executionObserved'])
            self.assertEqual(len(row['caller']['byteFingerprint']),64)
        self.assertEqual(self.path.read_bytes(),data);self.assertEqual(result['status'],'partial')
        limited=self.run_action(data,'android_method',limit=1,options={'method':{'class_descriptor':'LCalls;','name':'root','descriptor':'()V'}})['evidence']['methodCalls']
        self.assertEqual(limited['referenceCount'],2);self.assertEqual(len(limited['references']),1)
        self.assertTrue(limited['referencesTruncated']);self.assertIn('reference-budget',limited['coverage']['limitsReached'])

    @unittest.skipUnless(importlib.util.find_spec('androguard'),'optional Androguard not configured')
    def test_method_calls_preserve_ambiguous_definitions_and_reject_bad_operands(self):
        options={'method':{'class_descriptor':'LCalls;','name':'root','descriptor':'()V'}}
        duplicate=self.run_action(archive([('classes.dex',calls_fixture()),('classes2.dex',calls_fixture())]),'android_method',options=options)['evidence']['methodCalls']
        self.assertEqual(duplicate['selectionStatus'],'ambiguous-definition');self.assertEqual(duplicate['references'],[])
        bad=self.run_action(calls_fixture(b'\x71\x00\xff\xff\x00\x00\x0e\x00'),'android_method',options=options)['evidence']['methodCalls']
        self.assertGreater(bad['coverage']['decodeFailures'],0)
        self.assertFalse(any(r['relativeToSelection']=='callee' for r in bad['references']))
        missing=self.run_action(calls_fixture(),'android_method',options={'method':{'class_descriptor':'LCalls;','name':'missing','descriptor':'()V'}})['evidence']['methodCalls']
        self.assertEqual(missing['selectionStatus'],'no-covered-definition');self.assertEqual(missing['references'],[])

    @unittest.skipUnless(importlib.util.find_spec('androguard'),'optional Androguard not configured')
    def test_method_calls_enforce_instruction_code_and_dex_budgets(self):
        options={'method':{'class_descriptor':'LCalls;','name':'root','descriptor':'()V'}}
        many=self.run_action(calls_fixture(b'\x00\x00'*100001+b'\x0e\x00'),'android_method',options=options)['evidence']['methodCalls']
        self.assertEqual(many['coverage']['instructions'],100000)
        self.assertIn('instruction-budget',many['coverage']['limitsReached'])
        large=self.run_action(calls_fixture(b'\x00\x00'*524289+b'\x0e\x00'),'android_method',options=options)['evidence']['methodCalls']
        self.assertIn('code-byte-budget',large['coverage']['limitsReached']);self.assertLessEqual(large['coverage']['codeBytes'],1048576)
        entries=[('classes%d.dex'%i,reseal(calls_fixture().replace(b'LCalls;',('LCall%d;'%i).encode()))) for i in range(9)]
        bounded=self.run_action(archive(entries),'android_method',options={'method':{'class_descriptor':'LCall0;','name':'root','descriptor':'()V'}})['evidence']['methodCalls']
        self.assertEqual(bounded['coverage']['dexFiles'],8);self.assertIn('dex-budget',bounded['coverage']['limitsReached'])
        self.assertEqual(bounded['selectedDefinitionCount'],1)

    @unittest.skipUnless(importlib.util.find_spec('androguard'),'optional Androguard not configured')
    def test_exact_defined_dex_bytecode(self):
        result=self.run_action(dex_fixture(True),'android_method_code',options={'method':{'class_descriptor':'LFixture;','name':'native_work','descriptor':'()V'}})
        code=result['evidence']['selectedCode'][0];self.assertEqual(code['methods'][0]['instructions'][0]['name'],'return-void')
        self.assertEqual(code['coverage'],'selected-defined-method-bytecode-not-recovered-source-or-runtime-execution')
    @unittest.skipUnless(importlib.util.find_spec('lief') and importlib.util.find_spec('capstone'),'optional real engines not configured')
    def test_owned_compiled_native_references(self):
        # Owned C: noinline owned_add(a){return a+2;} owned_endpoint returns literal URL;
        # owned_caller calls owned_add(a)+3. GCC shared PIC O1, Bsymbolic, no build ID.
        # Compilation only; neither fixture nor a target process is executed.
        import base64
        data=base64.b64decode("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AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAPMPHvpIg+wISIsFwS8AAEiFwHQC/9BIg8QIwwAAAAAA/zXKLwAA/yXMLwAADx9AAP8lyi8AAGgAAAAA6eD///9IjT3BLwAASI0Fui8AAEg5+HQVSIsFbi8AAEiFwHQJ/+APH4AAAAAAww8fgAAAAABIjT2RLwAASI01ii8AAEgp/kiJ8EjB7j9IwfgDSAHGSNH+dBRIiwU9LwAASIXAdAj/4GYPH0QAAMMPH4AAAAAA8w8e+oA9TS8AAAB1K1VIgz0aLwAAAEiJ5XQMSI09Di0AAOhZ////6GT////GBSUvAAABXcMPHwDDDx+AAAAAAPMPHvrpd////41HAsNIjQX8DgAAw0iD7Ajo6////4PAA0iDxAjDAADzDx76SIPsCEiDxAjDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABodHRwczovL293bmVkLmludmFsaWQvbmF0aXZlAAAAAAEbAzssAAAABAAAAADw//9IAAAA2fD//3AAAADd8P//hAAAAOXw//+YAAAAAAAAABQAAAAAAAAAAXpSAAF4EAEbDAcIkAEAACQAAAAcAAAAsO///yAAAAAADhBGDhhKDwt3CIAAPxo7KjMkIgAAAAAQAAAARAAAAGHw//8EAAAAAAAAABAAAABYAAAAUfD//wgAAAAAAAAAFAAAAGwAAABF8P//EQAAAABEDhBMDggAAAAAAAAAAAAEAAAAIAAAAAUAAABHTlUAAQABwAQAAAABAAAAAAAAAAIAAcAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA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")
        self.assertEqual(hashlib.sha256(data).hexdigest(),"9340d3d111cd23cafea86f729fd641366deb5e755bba983ac8a53be96e4bb287")
        self.path.write_bytes(data)
        def select(symbol):return w.native_selection({'target':str(self.path),'options':{'function':{'symbol':symbol}}})['evidence']['selectedFunctions'][0]
        endpoint=select('owned_endpoint');caller=select('owned_caller');callee=select('owned_add')
        self.assertEqual(endpoint['image']['addressSpace'],'elf-link-time-virtual')
        self.assertEqual(endpoint['image']['runtimeBase'],'unknown')
        self.assertEqual(endpoint['disassembly']['engine'],'capstone')
        self.assertEqual(endpoint['strings'][0]['value'],'https://owned.invalid/native')
        self.assertEqual(caller['callees'][0]['targetAddressHex'],callee['addressHex'])
        meta,_=w.native_metadata(data,'owned',100)
        ambiguous=meta['segments']+meta['segments']
        body=w.disassemble_selected(data,endpoint,4096,ambiguous)
        self.assertEqual(body['strings'],[])
        self.assertEqual(w.disassemble_selected(data,endpoint,4096)['strings'],[])
    @unittest.skipUnless(importlib.util.find_spec('lief') and importlib.util.find_spec('capstone'),'optional real engines not configured')
    def test_bounded_indirect_register_calls_and_subregister_invalidation(self):
        for code,resolved in [(bytes.fromhex('48b8c000400000000000ffd0c3'),True),(bytes.fromhex('48b8c000400000000000b001ffd0c3'),False),(bytes.fromhex('48b8c000400000000000eb00ffd0c3'),False),(bytes.fromhex('ffd0c3'),False)]:
            self.path.write_bytes(elf_fixture(62,code));result=w.native_selection({'target':str(self.path),'options':{'function':{'symbol':'Java_Fixture_native_1work'}}})
            call=result['evidence']['selectedFunctions'][0]['indirectCalls'][0]
            self.assertEqual('targetAddressHex' in call,resolved)
            if resolved:self.assertEqual(call['targetAddressHex'],'0x4000c0')
            else:self.assertEqual(call['resolution'],'unknown-register-or-memory-target')

    def test_readiness_never_confuses_missing_engine_with_verified_execution(self):
        result=w.analysis_readiness()
        for check in result['evidence']['checks']:self.assertEqual(check['executionVerified'],check['status']=='completed')

class NativeCallTraversalTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.path=Path(self.temp.name)/'owned.so'
    def tearDown(self):self.temp.cleanup()
    def test_shared_installed_fixture_matches_owned_generator(self):
        import base64
        fixture=json.loads((HERE/'owned-native-call-fixture.json').read_text())
        expected=elf_fixture(62,bytes.fromhex('e801000000c3e801000000c3e8efffffffc3'),[('owned_root',0,6),('owned_child',6,6),('owned_leaf',12,6)])
        self.assertEqual(base64.b64decode(fixture['base64']),expected)
        self.assertEqual(hashlib.sha256(expected).hexdigest(),fixture['sha256'])
    def test_budget_rejects_unknown_boolean_fraction_and_excess(self):
        for budget in ({'shell':True},{'max_depth':True},{'max_depth':5},{'max_functions':0},{'max_edges':257},{'max_total_bytes':65537},{'max_depth':1.5},[]):
            with self.subTest(budget=budget),self.assertRaises(ValueError):w.native_call_budget(budget)
        self.assertEqual(w.native_call_budget({'max_depth':0})['max_depth'],0)
    def test_graph_caps_work_and_does_not_follow_heuristic_indirects(self):
        # Deterministic stdlib-only helper exercise; real engine tests below are separate.
        from unittest.mock import patch
        methods=[dict(id=str(i),name=str(i),addressHex=hex(100+i*10),architecture='x86_64',size=1,rangeValidation='mapped-file-backed-range') for i in range(4)]
        body={'status':'completed','requestedBytes':1,'decodedBytes':1,'byteFingerprint':'a'*64,'callees':[{'fromAddressHex':'0x64','targetAddressHex':m['addressHex'],'confidence':'decoded-direct-call-candidate'} for m in methods], 'indirectCalls':[{'fromAddressHex':'0x65','targetAddressHex':methods[3]['addressHex'],'resolution':'constant-register-static-candidate'}]}
        meta={'functionsTruncated':False,'segmentsTruncated':False,'segments':[]}
        with patch.object(w,'disassemble_selected',return_value={'status':'completed','requestedBytes':1,'decodedBytes':1}) as decode:
            result=w.native_call_traversal(b'',methods[0],body,methods,meta,w.native_call_budget({'max_functions':2}),1)
            self.assertEqual(decode.call_count,1);self.assertEqual(len(result['nodes']),2)
            self.assertIn('max_functions',result['coverage']['limitsReached'])
            self.assertEqual(result['edges'][-1]['resolution'],'indirect-not-followed')
            self.assertFalse(result['observedExecution']);self.assertEqual(result['status'],'partial')
            blocked=w.native_call_traversal(b'',methods[0],body,methods,meta,w.native_call_budget({'max_total_bytes':1}),1)
            self.assertEqual(len(blocked['nodes']),1);self.assertIn('max_total_bytes',blocked['coverage']['limitsReached'])
        # Multiple declared names at a target are ambiguous, not silently preferred.
        alias=dict(methods[1],id='alias',name='alias')
        graph=w.native_call_traversal(b'',methods[0],body,methods+[alias],meta,w.native_call_budget({'max_depth':0}),1)
        self.assertEqual(graph['edges'][1]['resolution'],'ambiguous-entry')
        self.assertEqual(graph['edges'][1]['matchCount'],2)
    def test_ambiguous_root_does_not_decode_outside_global_budget(self):
        from unittest.mock import patch
        self.path.write_bytes(b'owned')
        methods=[dict(id=str(i),name='duplicate',addressHex=hex(100+i*10)) for i in range(2)]
        meta={'segmentsTruncated':False,'segments':[],'functionsTruncated':False,'image':{}}
        with patch.object(w,'native_metadata',return_value=(meta,methods)),patch.object(w,'disassemble_selected') as decode:
            result=w.native_selection({'target':str(self.path),'options':{'function':{'symbol':'duplicate'},'native_calls':{'max_total_bytes':1}}})
            self.assertEqual(result['evidence']['callGraph']['matchCount'],2)
            self.assertEqual(result['evidence']['selectedFunctions'],[]);decode.assert_not_called()
    @unittest.skipUnless(importlib.util.find_spec('lief') and importlib.util.find_spec('capstone'),'optional real engines not configured')
    def test_real_multihop_cycle_and_all_global_budgets(self):
        # root -> child -> leaf -> root; each exact symbol owns six bytes.
        code=bytes.fromhex('e801000000c3e801000000c3e8efffffffc3')
        data=elf_fixture(62,code,[('owned_root',0,6),('owned_child',6,6),('owned_leaf',12,6)])
        self.path.write_bytes(data)
        def trace(budget=None,maximum=4096,selector=None):
            return w.native_selection({'target':str(self.path),'limit':1,'options':{'function':dict(selector or {'symbol':'owned_root'},max_bytes=maximum),'native_calls':budget or {}}})
        result=trace();graph=result['evidence']['callGraph']
        self.assertEqual([n['name'] for n in graph['nodes']],['owned_root','owned_child','owned_leaf'])
        self.assertEqual([n['depth'] for n in graph['nodes']],[0,1,2]);self.assertEqual(graph['usage']['requestedBytes'],18)
        self.assertEqual(graph['edges'][-1]['resolution'],'already-scheduled-or-visited')
        self.assertEqual(graph['coverage']['limitsReached'],[]);self.assertTrue(graph['coverage']['metadataRowsTruncated'])
        self.assertEqual(trace({'max_depth':0})['evidence']['callGraph']['edges'][0]['resolution'],'depth-limit')
        limited=trace({'max_total_bytes':7})['evidence']['callGraph']
        self.assertLessEqual(limited['usage']['requestedBytes'],7);self.assertIn('partial-or-blocked-function',limited['coverage']['limitsReached'])
        self.assertEqual(trace({'max_functions':1})['evidence']['callGraph']['edges'][0]['resolution'],'function-limit')
        edge_limited=trace({'max_edges':1})['evidence']['callGraph']
        self.assertEqual(len(edge_limited['edges']),1);self.assertIn('max_edges',edge_limited['coverage']['limitsReached'])
        self.assertEqual(trace(maximum=1)['evidence']['callGraph']['nodes'][0]['decodedBytes'],0)
        missing=trace(selector={'symbol':'absent'})['evidence']['callGraph'];self.assertEqual(missing['nodes'],[])
        self.assertEqual(self.path.read_bytes(),data)
    @unittest.skipUnless(importlib.util.find_spec('lief') and importlib.util.find_spec('capstone'),'optional real engines not configured')
    def test_real_unmapped_indirect_and_blocked_extent_remain_explicit(self):
        fixtures=[(bytes.fromhex('e801000000c3c3'),[('root',0,6),('zero',6,0)],'exact-entry-scheduled'),(bytes.fromhex('e87b000000c3'),[('root',0,6)],'no-exact-symbol-entry'),(bytes.fromhex('48b8c000400000000000ffd0c3'),[('root',0,13)],'indirect-not-followed'),(bytes.fromhex('e801000000c3c3'),[('root',0,6),('one',6,1),('alias',6,1)],'ambiguous-entry')]
        for code,entries,resolution in fixtures:
            self.path.write_bytes(elf_fixture(62,code,entries));graph=w.native_selection({'target':str(self.path),'options':{'function':{'symbol':'root'},'native_calls':{}}})['evidence']['callGraph']
            self.assertEqual(graph['edges'][0]['resolution'],resolution)
            if entries[-1][0]=='zero':self.assertEqual(graph['nodes'][1]['status'],'blocked')
    @unittest.skipUnless(importlib.util.find_spec('lief') and importlib.util.find_spec('capstone'),'optional real engines not configured')
    def test_real_arm64_indirect_is_retained_without_following(self):
        self.path.write_bytes(elf_fixture(183,bytes.fromhex('00003fd6c0035fd6')))
        graph=w.native_selection({'target':str(self.path),'options':{'function':{'address':'0x4000c0'},'native_calls':{}}})['evidence']['callGraph']
        self.assertEqual(len(graph['nodes']),1);self.assertEqual(graph['edges'][0]['resolution'],'indirect-not-followed')


if __name__=='__main__':unittest.main()
