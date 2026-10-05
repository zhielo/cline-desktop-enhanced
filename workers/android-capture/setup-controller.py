"""Explicit operator-run bootstrap inside an ALREADY isolated Linux controller.
Does not create a VM, alter host networking, enroll a device or run a sample.
"""
import argparse, os, re, shlex, shutil, subprocess, sys, venv, ssl
from pathlib import Path
HOOKS=['CLINE_ANDROID_ISOLATION_CHECK','CLINE_ANDROID_RESET','CLINE_ANDROID_CLEANUP','CLINE_ANDROID_ADB','CLINE_ANDROID_APKANALYZER']
ACK='operator-enforced-disposable-android-and-denied-egress'

def plan(directory,cert,key,environ):
    if not sys.platform.startswith('linux'):raise ValueError('Existing isolated Linux controller required')
    output=Path(directory)
    if not output.is_absolute() or output.exists() or output.resolve()!=output:raise ValueError('New canonical absolute private directory required')
    if environ.get('CLINE_ANDROID_ISOLATION_ACK')!=ACK:raise ValueError('Operator isolation acknowledgment required')
    if environ.get('CLINE_ANDROID_PHYSICAL_POLICY_ACK')!='dedicated-authorized-device-with-operator-cleanup':raise ValueError('Dedicated physical device and reviewed cleanup policy required')
    serial=environ.get('CLINE_ANDROID_DEVICE_SERIAL','');worker=environ.get('CLINE_ANDROID_WORKER_ID','')
    if not re.fullmatch(r'[A-Za-z0-9_.:-]{1,128}',serial) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,128}',worker):raise ValueError('Explicit device serial and worker ID required')
    for name in HOOKS:
        path=Path(environ.get(name,''))
        if not path.is_absolute() or path.is_symlink() or not path.is_file() or not os.access(path,os.X_OK):raise ValueError('Missing trusted executable: '+name)
    for item in [cert,key]:
        path=Path(item)
        if not path.is_absolute() or path.is_symlink() or not path.is_file():raise ValueError('Existing TLS certificate/key required')
    ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER).load_cert_chain(cert,key)
    bun=shutil.which('bun')
    if not bun:raise ValueError('Pinned Bun 1.3.14 must be installed by the operator')
    probe=subprocess.run([bun,'--version'],check=True,capture_output=True,text=True,timeout=5)
    if probe.stdout.strip()!='1.3.14':raise ValueError('Use pinned Bun 1.3.14')
    return output,bun

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--directory',required=True);parser.add_argument('--tls-cert',required=True);parser.add_argument('--tls-key',required=True);parser.add_argument('--apply',action='store_true');args=parser.parse_args()
    directory,bun=plan(args.directory,args.tls_cert,args.tls_key,os.environ)
    if not args.apply:print('Validated dry run. --apply installs pinned dependencies and creates private credentials. No VM or device is provisioned.');return
    subprocess.run([os.environ['CLINE_ANDROID_ISOLATION_CHECK']],check=True,timeout=30,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    directory.mkdir(mode=0o700);source=Path(__file__).resolve().parent;environment=directory/'.venv'
    venv.EnvBuilder(with_pip=True).create(environment);python=environment/'bin/python'
    subprocess.run([str(python),'-m','pip','install','--disable-pip-version-check','-r',str(source/'requirements.txt')],check=True,timeout=1200)
    subprocess.run([bun,'install','--frozen-lockfile'],cwd=source,check=True,timeout=600);subprocess.run([bun,'run','build'],cwd=source,check=True,timeout=120)
    # Secret generation runs inside the pinned venv; stdout never contains values.
    generate="""import os,secrets,sys
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
root=Path(sys.argv[1]);key=Ed25519PrivateKey.generate()
values={'signing.pem':key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()),'public.pem':key.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo),'token':secrets.token_urlsafe(32).encode()}
for name,value in values.items():
 with os.fdopen(os.open(root/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),'wb') as file:file.write(value)
"""
    subprocess.run([str(python),'-I','-c',generate,str(directory)],check=True,timeout=30)
    variables={name:os.environ[name] for name in HOOKS+['CLINE_ANDROID_DEVICE_SERIAL','CLINE_ANDROID_WORKER_ID','CLINE_ANDROID_ISOLATION_ACK','CLINE_ANDROID_PHYSICAL_POLICY_ACK']}
    variables.update(CLINE_ANDROID_SIGNING_KEY=str(directory/'signing.pem'),CLINE_ANDROID_WORKER_TOKEN=(directory/'token').read_text(),CLINE_ANDROID_WORKER_DATA=str(directory/'data'),CLINE_ANDROID_TLS_CERT=args.tls_cert,CLINE_ANDROID_TLS_KEY=args.tls_key)
    with os.fdopen(os.open(directory/'controller.env',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),'w') as file:
        file.write('\n'.join('export '+name+'='+shlex.quote(value) for name,value in variables.items())+'\n')
    print('Controller prepared. Private configuration: '+str(directory/'controller.env')+'. No server, VM or target was started. Protect the token/key and configure desktop pinning separately.')
if __name__=='__main__':main()
