[BITS 64]
global _start
_start:
	xor		rdx, rdx
	mov		rcx, 4
	div		rcx
