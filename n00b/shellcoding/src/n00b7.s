[BITS 64]
global _start
_start:
	mov		rdi, 42
	mov		rax, 60
	syscall
