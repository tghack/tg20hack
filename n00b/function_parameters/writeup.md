# Function Parameters writeup
**Author: PewZ**

**Difficulty: n00b**

**Category: n00b**

---

It's a bit more complicated this time. Using the single-step mode can help
us out if we're not getting the desired values.

Following is the assembly code we will send to the server:
```asm
	mov		rax, 4
	mul		rdi
	add		rax, 3
	ret
```
We start by calculating `a * 4` by multiplying `rdi` with `rax`. The argument
to the function is in `rdi`, and we set `rax` to 4.
Then we add `3` to `rax` and return.

```console
$ nc shellcode.tghack.no 1111
Welcome!
Do you want single-step mode? (Y/N) n
Level: 5
Please give me some assembly code, end with EOF
mov rax, 4
mul rdi
add rax, 3
ret
EOF
code:
push    195939070
mov     rdi, 3080
call    func
ret
func:
mov rax, 4
mul rdi
add rax, 3
ret

0x1000:	push	0xbadcafe
0x1005:	mov	rdi, 0xc08
0x100c:	call	0x1012
0x1012:	mov	rax, 4
0x1019:	mul	rdi
0x101c:	add	rax, 3
0x1020:	ret
0x1011:	ret
Emulation done!
RAX: 0x3023
RBX: 0x0
RCX: 0x0
RDX: 0x0
RSI: 0x0
RDI: 0xc08
RBP: 0x0
RSP: 0x201000
Level 5 successful!
TG20{parameters_sure_are_nice_to_have}
```
