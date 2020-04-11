# Introduction to Functions
**Author: PewZ**

**Difficulty: n00b**

**Category: n00b**

---

For this task we have to create a tiny function that simply returns 0.
To do this we set `rax` to `0` and then return using the `ret` instruction.

```
$ nc shellcode.tghack.no 1111
Welcome!
Do you want single-step mode? (Y/N) n
Level: 4
Please give me some assembly code, end with EOF
mov rax, 0
ret
EOF
code:
push    195939070
call    func
ret
func:
mov rax, 0
ret

0x1000:	push	0xbadcafe
0x1005:	call	0x100b
0x100b:	mov	rax, 0
0x1012:	ret
0x100a:	ret
Emulation done!
RAX: 0x0
RBX: 0x0
RCX: 0x0
RDX: 0x0
RSI: 0x0
RDI: 0x0
RBP: 0x0
RSP: 0x201000
0
Level 4 successful!
TG20{is_this_functional_programming?}
```
