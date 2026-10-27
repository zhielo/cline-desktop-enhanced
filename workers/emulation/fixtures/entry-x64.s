.global _start
.text
_start:
 mov $60, %rax
 mov $7, %rdi
 syscall
