/* Owned no-libc JNI fixture. No OS libraries or target downloads required. */
int JNI_OnLoad(void *vm, void *unused) { return 0x10006; }
int Java_com_cline_Owned_transform(void *env, void *clazz, int value) {
#ifdef CLINE_OWNED_DENIED_SYSCALL
 __asm__ volatile("svc #0" ::: "memory");
#endif
 return (value ^ 0x55) + 7; }
