.global _start
.text
_start:
 mov x0, #1
 adr x1, message
 mov x2, #12
 mov x8, #64
 svc #0
 mov x0, #7
 mov x8, #93
 svc #0
message:
 .ascii "cline-owned\n"
