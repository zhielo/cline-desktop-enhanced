.global _start
.syntax unified
.arm
.text
_start:
 mov r0, #1
 adr r1, message
 mov r2, #12
 mov r7, #4
 svc #0
 mov r0, #7
 mov r7, #1
 svc #0
message:
 .ascii "cline-owned\n"
