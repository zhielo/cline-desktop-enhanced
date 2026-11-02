/* Two unchanged Apache-2.0 unidbg bridge functions, commit
 * ee936a4bedb02b1e2d61533275246c49ed390e22. Test-only JNI/backend stubs;
 * no emulator, native dependency or target is loaded. */
JNIEXPORT void JNICALL Java_com_github_unidbg_arm_backend_unicorn_Unicorn_mem_1write
  (JNIEnv *env, jclass cls, jlong handle, jlong address, jbyteArray bytes) {
  t_unicorn unicorn = (t_unicorn) handle;
  uc_engine *eng = unicorn->uc;
  jbyte *array = (*env)->GetByteArrayElements(env, bytes, NULL);
  jsize size = (*env)->GetArrayLength(env, bytes);
  uc_err err = uc_mem_write(eng, (uint64_t)address, array, (size_t)size);
  if (err != UC_ERR_OK) {
    throwException(env, err);
  }
  (*env)->ReleaseByteArrayElements(env, bytes, array, JNI_ABORT);
}

JNIEXPORT jbyteArray JNICALL Java_com_github_unidbg_arm_backend_unicorn_Unicorn_mem_1read
  (JNIEnv *env, jclass cls, jlong handle, jlong address, jlong size) {
  t_unicorn unicorn = (t_unicorn) handle;
  uc_engine *eng = unicorn->uc;
  jbyteArray bytes = (*env)->NewByteArray(env, (jsize)size);
  jbyte *array = (*env)->GetByteArrayElements(env, bytes, NULL);
  uc_err err = uc_mem_read(eng, (uint64_t)address, array, (size_t)size);
  if (err != UC_ERR_OK) {
    throwException(env, err);
  }
  (*env)->ReleaseByteArrayElements(env, bytes, array, 0);
  return bytes;
}

