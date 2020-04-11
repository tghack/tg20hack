# Registers Everywhere Writeup
**Author: PewZ**

**Difficulty: n00b**

**Category: n00b**

---

We can use `mov` instructions to move the correct values into their respective
registers, like the table below:

| Register name | Value |
|:-----------:|:---:|
| rax | 42 |
| rbx | 13 |
| rcx | 37 |
| rdi | 0 |
| rsi | 1337 |

```
$ nc shellcode.tghack.no 1111
Welcome!
Do you want single-step mode? (Y/N) n
Level: 2
Please give me some assembly code, end with EOF
mov rax, 42
mov rbx, 13
mov rcx, 37
mov rdi, 0
mov rsi, 1337
EOF
code: mov rax, 42
mov rbx, 13
mov rcx, 37
mov rdi, 0
mov rsi, 1337

0x1000:	mov	rax, 0x2a
0x1007:	mov	rbx, 0xd
0x100e:	mov	rcx, 0x25
0x1015:	mov	rdi, 0
0x101c:	mov	rsi, 0x539
Emulation done!
RAX: 0x2a
RBX: 0xd
RCX: 0x25
RDX: 0x0
RSI: 0x539
RDI: 0x0
RBP: 0x0
RSP: 0x0
Level 2 successful!
TG20{some_setup_required}
```
