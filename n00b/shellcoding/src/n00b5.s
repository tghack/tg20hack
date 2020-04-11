[BITS 64]
global _start
_start:
	mov		rax, 4
	mul		rdi
	add		rax, 3
	ret
