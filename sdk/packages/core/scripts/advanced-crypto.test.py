import unittest,json,types,tempfile,os,base64,zipfile,io
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM,ChaCha20Poly1305
source=Path(__file__).resolve().parents[1]/'src/extensions/tools/executors/advanced-analysis-worker.ts'
w=types.ModuleType('owned_worker');w.__file__=str(source);exec(json.loads(source.read_text().split('export const ADVANCED_ANALYSIS_WORKER =',1)[1].strip().removesuffix(';')),w.__dict__)
class AuthenticatedCryptoTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);self.key=os.urandom(32);self.nonce=os.urandom(12);self.keyfile=self.root/'private-key.raw';self.keyfile.write_bytes(self.key);self.keyfile.chmod(0o600);self.before={name:os.environ.get(name) for name in ['CLINE_RE_ALLOW_DECRYPTION','CLINE_RE_PRIVATE_KEY_FILE']};self.configure()
 def configure(self):os.environ['CLINE_RE_ALLOW_DECRYPTION']='1';os.environ['CLINE_RE_PRIVATE_KEY_FILE']=str(self.keyfile)
 def tearDown(self):
  for name,value in self.before.items():
   if value is None:os.environ.pop(name,None)
   else:os.environ[name]=value
  self.temp.cleanup()
 def run_cipher(self,ciphertext,algorithm='aes-256-gcm',**kwargs):
  self.configure();target=self.root/'ciphertext.bin';target.write_bytes(ciphertext);settings={'algorithm':algorithm,'nonce_hex':self.nonce.hex(),**kwargs};return w.main({'action':'decrypt_blob','target':str(target),'options':{'decrypt':settings}})
 def test_aes_authentication_and_no_plaintext_report(self):
  plaintext=b'owned confidential fixture';result=self.run_cipher(AESGCM(self.key).encrypt(self.nonce,plaintext,b''));self.assertEqual(result['status'],'completed');self.assertTrue(result['evidence']['authenticated']);self.assertEqual(result['evidence']['recoveredSha256'],w.digest(plaintext));serialized=json.dumps(result);self.assertNotIn(plaintext.decode(),serialized);self.assertNotIn(self.key.hex(),serialized);self.assertNotIn(str(self.keyfile),serialized)
 def test_chacha(self):
  plain=b'owned chacha fixture';result=self.run_cipher(ChaCha20Poly1305(self.key).encrypt(self.nonce,plain,b''),'chacha20-poly1305');self.assertEqual(result['evidence']['recoveredSha256'],w.digest(plain))
 def test_wrong_key(self):
  ciphertext=AESGCM(self.key).encrypt(self.nonce,b'owned',b'');self.keyfile.write_bytes(os.urandom(32))
  with self.assertRaisesRegex(ValueError,'authentication failed'):self.run_cipher(ciphertext)
 def test_tampered_tag(self):
  ciphertext=bytearray(AESGCM(self.key).encrypt(self.nonce,b'owned',b''));ciphertext[-1]^=1
  with self.assertRaisesRegex(ValueError,'authentication failed'):self.run_cipher(bytes(ciphertext))
 def test_associated_data(self):
  aad=b'owned associated data';ciphertext=AESGCM(self.key).encrypt(self.nonce,b'owned',aad);result=self.run_cipher(ciphertext,aad_hex=aad.hex());self.assertEqual(result['evidence']['associatedDataSha256'],w.digest(aad))
 def test_wrong_associated_data(self):
  ciphertext=AESGCM(self.key).encrypt(self.nonce,b'owned',b'correct')
  with self.assertRaisesRegex(ValueError,'authentication failed'):self.run_cipher(ciphertext,aad_hex=b'wrong'.hex())
 def test_host_gate(self):
  os.environ.pop('CLINE_RE_ALLOW_DECRYPTION',None)
  with self.assertRaises(w.Blocked):w.decrypt_blob(b'owned',{'decrypt':{'algorithm':'aes-256-gcm','nonce_hex':self.nonce.hex()}},100)
 def test_invalid_key_length(self):
  self.keyfile.write_bytes(b'short')
  with self.assertRaises(w.Blocked):self.run_cipher(AESGCM(self.key).encrypt(self.nonce,b'owned',b''))
 @unittest.skipIf(os.name=='nt','POSIX mode fixture; Windows ACL verification is host-owned')
 def test_unsafe_key_permissions(self):
  self.keyfile.chmod(0o644)
  with self.assertRaises(w.Blocked):self.run_cipher(AESGCM(self.key).encrypt(self.nonce,b'owned',b''))
 def test_prefix_decoding_receipt(self):
  plaintext=b'owned encoded ciphertext';ciphertext=AESGCM(self.key).encrypt(self.nonce,plaintext,b'');target=self.root/'encoded.bin';target.write_bytes(base64.b64encode(ciphertext));result=w.main({'action':'decrypt_blob','target':str(target),'options':{'steps':['base64'],'decrypt':{'algorithm':'aes-256-gcm','nonce_hex':self.nonce.hex()}}});self.assertEqual(result['evidence']['recoveredSha256'],w.digest(plaintext));self.assertEqual(result['evidence']['prefixTransformReceipts'][0]['step'],'base64')
 def test_recovered_archive_and_temporary_cleanup(self):
  data=io.BytesIO()
  with zipfile.ZipFile(data,'w') as archive:archive.writestr('owned.txt',b'owned private data')
  before=set(Path.cwd().glob('recovered-*'));result=self.run_cipher(AESGCM(self.key).encrypt(self.nonce,data.getvalue(),b''),analysis='structured');self.assertEqual(result['evidence']['recoveredFormat'],'zip');self.assertEqual(result['evidence']['analysisStages'][1]['evidence']['entryCount'],1);self.assertEqual(set(Path.cwd().glob('recovered-*')),before);self.assertFalse(result['evidence']['plaintextPersisted'])
 def test_key_grant_removed_before_parsing(self):
  self.run_cipher(AESGCM(self.key).encrypt(self.nonce,b'owned',b''));self.assertNotIn('CLINE_RE_PRIVATE_KEY_FILE',os.environ)
 def test_nonce_rejected(self):
  with self.assertRaises(ValueError):self.run_cipher(b'owned',nonce_hex='00')
 def test_trailing_compressed_stream_rejected(self):
  import zlib
  with self.assertRaises(ValueError):w.apply_transform_steps(zlib.compress(b'owned')+b'uninspected', ['zlib'])
if __name__=='__main__':unittest.main(verbosity=2)
