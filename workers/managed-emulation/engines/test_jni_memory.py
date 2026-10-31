"""Compile only two patched JNI functions against owned fake JNI/Unicorn calls.

No JDK, emulator, native engine library, unknown binary or network is used.
The build still applies exact unique contexts to the separately pinned source.
"""
from pathlib import Path
import os
import subprocess
import tempfile
import unittest
import native_rebuild as native

HERE = Path(__file__).resolve().parent
# Owned fault-injection implementation, not a copy of JNI/Unicorn libraries.
HARNESS = r'''
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define JNIEXPORT
#define JNICALL
#define JNI_ABORT 2
#define UC_ERR_OK 0
#define UC_ERR_ARG 15
#define UC_ERR_READ_UNMAPPED 6
typedef int64_t jlong;
typedef int32_t jsize;
typedef signed char jbyte;
typedef void *jclass;
typedef void *jbyteArray;
typedef int uc_err;
typedef struct { int unused; } uc_engine;
typedef struct { uc_engine *uc; } *t_unicorn;
struct FakeJNI;
typedef const struct FakeJNI *JNIEnv;
struct FakeJNI {
 int (*ExceptionCheck)(JNIEnv *);
 jsize (*GetArrayLength)(JNIEnv *, jbyteArray);
 jbyte *(*GetByteArrayElements)(JNIEnv *, jbyteArray, void *);
 void (*ReleaseByteArrayElements)(JNIEnv *, jbyteArray, jbyte *, int);
 jbyteArray (*NewByteArray)(JNIEnv *, jsize);
};
static int pending,mode,length_calls,pin_calls,release_calls,allocation_calls,native_calls,throws,last_release;
static jsize length;
static jbyte data[4];
static void require(int value) { if (!value) exit(99); }
static int exception_check(JNIEnv *env) { (void)env; return pending; }
static jsize get_length(JNIEnv *env,jbyteArray a) {
 (void)env; require(!pending && a==data); ++length_calls;
 if (mode==4) pending=1;
 return length;
}
static jbyte *pin(JNIEnv *env,jbyteArray a,void *copy) {
 (void)env;(void)copy;require(!pending && a==data);++pin_calls;
 if (mode==3) {pending=1;return NULL;}
 return data;
}
static void release(JNIEnv *env,jbyteArray a,jbyte *p,int release_mode) {
 (void)env;require(a==data && p==data);++release_calls;last_release=release_mode;
}
static jbyteArray allocate(JNIEnv *env,jsize size) {
 (void)env;require(!pending && size>=0 && size<=4);++allocation_calls;
 if (mode==2) {pending=1;return NULL;}
 return data;
}
static void throwException(JNIEnv *env,uc_err error) {
 (void)env;require(!pending && error!=UC_ERR_OK);
 if(native_calls) require(release_calls==1);
 ++throws;pending=1;
}
static uc_err uc_mem_write(uc_engine *eng,uint64_t address,const void *p,size_t size) {
 (void)eng;(void)address;require(!pending && p==data && size==4);++native_calls;
 return mode==5 ? UC_ERR_READ_UNMAPPED : UC_ERR_OK;
}
static uc_err uc_mem_read(uc_engine *eng,uint64_t address,void *p,size_t size) {
 return uc_mem_write(eng,address,p,size);
}
static const struct FakeJNI functions={exception_check,get_length,pin,release,allocate};
static JNIEnv env=&functions;
static uc_engine engine;
static struct { uc_engine *uc; } instance={&engine};
static void reset(int fault) {
 pending=fault==1;mode=fault;length=4;
 length_calls=pin_calls=release_calls=allocation_calls=native_calls=throws=0;last_release=-1;
}
'''
DRIVER = r'''
int main(int argc,char **argv) {
 require(argc==2);
 int scenario=atoi(argv[1]);
 jlong handle=(jlong)(intptr_t)&instance;
 if(scenario>=0 && scenario<=5) {
  int fault=scenario;
  reset(fault);
  jbyteArray value=Java_com_github_unidbg_arm_backend_unicorn_Unicorn_mem_1read(&env,NULL,handle,0,4);
  if(fault==1) require(!value && !allocation_calls && !pin_calls && !native_calls && !throws);
  if(fault==2) require(!value && allocation_calls==1 && !pin_calls && !native_calls && !throws);
  if(fault==3) require(!value && allocation_calls==1 && pin_calls==1 && !release_calls && !native_calls && !throws);
  if(fault==0 || fault==4) require(value==data && native_calls==1 && release_calls==1 && last_release==0 && !pending);
  if(fault==5) require(!value && native_calls==1 && release_calls==1 && last_release==JNI_ABORT && throws==1);
 } else if(scenario>=6 && scenario<=9) {
  const jlong invalid[]={-1,INT64_MIN,(jlong)INT32_MAX+1,INT64_MAX};
  reset(0);
  require(!Java_com_github_unidbg_arm_backend_unicorn_Unicorn_mem_1read(&env,NULL,handle,0,invalid[scenario-6]));
  require(throws==1 && !allocation_calls && !pin_calls && !native_calls);
 } else if(scenario==10) {
  reset(0);
  require(Java_com_github_unidbg_arm_backend_unicorn_Unicorn_mem_1read(&env,NULL,handle,0,0)==data);
  require(allocation_calls==1 && !pin_calls && !native_calls && !release_calls);
 } else if(scenario>=11 && scenario<=16) {
  int fault=scenario-11;
  reset(fault);
  Java_com_github_unidbg_arm_backend_unicorn_Unicorn_mem_1write(&env,NULL,handle,0,data);
  if(fault==1) require(!length_calls && !pin_calls && !native_calls && !throws);
  if(fault==3) require(length_calls==1 && pin_calls==1 && !release_calls && !native_calls && !throws);
  if(fault==4) require(length_calls==1 && !pin_calls && !native_calls && !throws);
  if(fault==0 || fault==2) require(native_calls==1 && release_calls==1 && last_release==JNI_ABORT && !pending);
  if(fault==5) require(native_calls==1 && release_calls==1 && last_release==JNI_ABORT && throws==1);
 } else if(scenario==17) {
  reset(0);
  Java_com_github_unidbg_arm_backend_unicorn_Unicorn_mem_1write(&env,NULL,handle,0,NULL);
  require(throws==1 && !length_calls && !pin_calls && !native_calls);
 } else if(scenario==18) {
  reset(0);length=0;
  Java_com_github_unidbg_arm_backend_unicorn_Unicorn_mem_1write(&env,NULL,handle,0,data);
  require(length_calls==1 && !pin_calls && !native_calls && !release_calls);
 } else require(0);
 puts("CLINE_OWNED_JNI_MEMORY_V1 passed");
 return 0;
}
'''

class MemoryTests(unittest.TestCase):
    def test_exact_context_and_double_application_refused(self):
        source=(HERE/'jni_memory_fixture.c').read_text()
        patched=native.patch_memory_arrays(source)
        with self.assertRaises(ValueError): native.patch_memory_arrays(patched)
        with self.assertRaises(ValueError): native.patch_memory_arrays(source+source)
        with self.assertRaises(ValueError): native.patch_memory_arrays(source.replace('jsize size =','jsize changed ='))

    def test_compiled_fault_paths_and_original_regression(self):
        source=(HERE/'jni_memory_fixture.c').read_text()
        with tempfile.TemporaryDirectory(prefix='cline-owned-jni-memory-') as directory:
            root=Path(directory)
            for name,body in [('patched',native.patch_memory_arrays(source)),('original',source)]:
                code=root/(name+'.c');binary=root/name
                code.write_text(HARNESS+body+DRIVER)
                # Only the fixed owned fake implementation above is executed.
                subprocess.run(['cc','-std=c11','-Wall','-Wextra','-Werror','-Wno-unused-parameter','-O2',str(code),'-o',str(binary)],check=True,capture_output=True,timeout=30,env={'PATH':os.defpath,'LANG':'C'})
                for scenario in range(19):
                    # Unchanged ordinary success paths also pass on original.
                    # Every corrected boundary must independently reject the
                    # unpatched function; the first failure cannot hide others.
                    expected=99 if name=='original' and scenario not in (0,4,11,13) else 0
                    with self.subTest(source=name,scenario=scenario):
                        result=subprocess.run([str(binary),str(scenario)],capture_output=True,timeout=5,env={'PATH':os.defpath,'LANG':'C'})
                        self.assertEqual(result.returncode,expected,result.stderr)
                        self.assertEqual(result.stderr,b'')
                        self.assertEqual(result.stdout,b'CLINE_OWNED_JNI_MEMORY_V1 passed\n' if expected==0 else b'')

if __name__=='__main__':unittest.main()
