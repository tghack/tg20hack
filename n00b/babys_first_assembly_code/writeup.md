# Baby's First Assembly Code
**Author: PewZ**

**Difficulty: n00b**

**Category: n00b**

---

For this task we have to set the `rax` register to 0. We can either move `0`
into `rax` or use `xor rax, rax`.

```console
$ nc shellcode.tghack.no 1111
Welcome!
Do you want single-step mode? (Y/N) N
Level: 1
Please give me some assembly code, end with EOF
mov rax, 0
EOF
code: mov rax, 0

0x1000:	mov rax, 0
Emulation done!
RAX: 0x0
RBX: 0x0
RCX: 0x0
RDX: 0x0
RSI: 0x0
RDI: 0x0
RBP: 0x0
RSP: 0x0
Level 1 successful!
TG20{welcome_to_the_world_of_assembly}
```
