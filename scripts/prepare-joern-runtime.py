"""Prepare the reviewed Linux Joern runtime; never downloads or executes an input.
Usage: python scripts/prepare-joern-runtime.py ARCHIVE JDK_HOME NEW_DESTINATION
Keep the printed manifest fingerprint in trusted host configuration, not model input.
"""
import hashlib, json, os, pathlib, shutil, sys, zipfile
VERSION='4.0.662'
SHA256='fa86ee74ce8ceaa5780732328966afc5e7771048e68a276caac7843e694e9499'
def digest(path):
 h=hashlib.sha256()
 with path.open('rb') as f:
  for chunk in iter(lambda:f.read(1024*1024),b''):h.update(chunk)
 return h.hexdigest()
def main():
 archive,jdk,dest=map(lambda s:pathlib.Path(s).resolve(),sys.argv[1:])
 if sys.platform!='linux' or dest.exists() or not (jdk/'bin/java').is_file():raise ValueError('Linux, reviewed JDK and new destination required')
 if digest(archive)!=SHA256:raise ValueError('Official Joern archive checksum mismatch')
 dest.mkdir(mode=0o700,parents=True)
 try:
  with zipfile.ZipFile(archive) as z:
   members=z.infolist()
   if sum(i.file_size for i in members)>8*1024**3:raise ValueError('Archive expansion budget')
   for i in members:
    p=pathlib.PurePosixPath(i.filename)
    if p.is_absolute() or '..' in p.parts or not p.parts or p.parts[0]!='joern-cli' or ((i.external_attr>>16)&0o170000)==0o120000:raise ValueError('Unexpected archive path/type')
    target=dest.joinpath(*p.parts[1:])
    if i.is_dir():target.mkdir(parents=True,exist_ok=True);continue
    target.parent.mkdir(parents=True,exist_ok=True)
    with z.open(i) as source,target.open('wb') as out:shutil.copyfileobj(source,out)
    # Python zip extraction does not preserve executable bits. Native astgen
    # also needs them, not just shell launchers. Preserve reviewed archive modes.
    mode=(i.external_attr>>16)&0o777
    with target.open('rb') as f:magic=f.read(4)
    target.chmod(0o600 | (mode&0o100) | (0o100 if magic.startswith(b'#!') or magic==b'\x7fELF' else 0))
  shutil.copytree(jdk,dest/'jdk',symlinks=False)
  for p in dest.rglob('*'):
   if p.is_symlink():raise ValueError('Unexpected runtime symlink')
  manifest={'version':VERSION,'files':{p.relative_to(dest).as_posix():digest(p) for p in sorted(dest.rglob('*')) if p.is_file()}}
  raw=json.dumps(manifest,sort_keys=True,separators=(',',':')).encode();(dest/'cline-runtime.json').write_bytes(raw)
  print(json.dumps({'CLINE_JOERN_HOME':str(dest),'CLINE_JOERN_MANIFEST_SHA256':hashlib.sha256(raw).hexdigest(),'version':VERSION}))
 except BaseException:
  shutil.rmtree(dest);raise
if __name__=='__main__':main()
