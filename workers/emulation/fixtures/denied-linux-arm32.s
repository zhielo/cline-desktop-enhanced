.global _start
.syntax unified
.arm
.text
_start:
 movw r7, #322
 svc #0
 mov r0, #7
 mov r7, #1
 svc #0
