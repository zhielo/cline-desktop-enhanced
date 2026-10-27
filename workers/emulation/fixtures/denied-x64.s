.global _start
.text
_start:
 mov $257, %rax
 syscall
 mov $60, %rax
 mov $7, %rdi
 syscall
