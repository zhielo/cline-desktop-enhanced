.global _start
.text
_start:
 mov $1, %rax
 mov $1, %rdi
 lea message(%rip), %rsi
 mov $12, %rdx
 syscall
 mov $60, %rax
 mov $7, %rdi
 syscall
.section .rodata
message:
 .ascii "cline-owned\n"
