[BITS 64]
global _start
_start:
	mov		rax, rdi
	mul		rsi
	ret
