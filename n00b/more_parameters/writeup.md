# More Parameters writeup
**Author: PewZ**

**Difficulty: n00b**

**Category: n00b**

---

Create a function that takes two parameters, multiplies them together and
returns the result.

The equivalent in C would be something like this:
```C
int func(int a, int b)
{
	return a * b;
}
```

Even though we are dealing with two parameters this time, the code ends up a
little bit simpler than in the previous challenge.

We start by by moving the first argument (`rdi`) into `rax` and multiplying with
the second argument (`rsi`) by running `mul rsi`. Note that `mul` implicitly
uses `rax` as the other operand.

```console
$ nc shellcode.tghack.no 1111
Welcome!
Do you want single-step mode? (Y/N) n
Level: 6
Please give me some assembly code, end with EOF
mov rax, rdi
mul rsi
ret
EOF
code: 
push    195939070
mov     rdi, 9086
mov     rsi, 8976
call    func
ret
func:
mov rax, rdi
mul rsi
ret

0x1000:	push	0xbadcafe
0x1005:	mov	rdi, 0x237e
0x100c:	mov	rsi, 0x2310
0x1013:	call	0x1019
0x1019:	mov	rax, rdi
0x101c:	mul	rsi
0x101f:	ret	
0x1018:	ret	
Emulation done!
RAX: 0x4dc71e0
RBX: 0x0
RCX: 0x0
RDX: 0x0
RSI: 0x2310
RDI: 0x237e
RBP: 0x0
RSP: 0x201000
Level 6 successful!
TG20{two_parameters!}
```
