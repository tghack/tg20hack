# Division
**Author: PewZ**

**Difficulty: n00b**

**Category: n00b**

---

`rax` will be set up to contain some random value. Our goal is to divide `rax`
by `4`. We can accomplish this by using the `div` instruction. Note that `div`
uses the register pair `rdx:rax` for division, so clear `rdx` to make sure
that we only use the value in `rax`.

```
$ nc shellcode.tghack.no 1111
Welcome!
Do you want single-step mode? (Y/N) n
Level: 3
Please give me some assembly code, end with EOF
xor rdx, rdx
mov rcx, 4
div rcx
EOF
code: xor rdx, rdx
mov rcx, 4
div rcx

0x1000:	xor	rdx, rdx
0x1003:	mov	rcx, 4
0x100a:	div	rcx
Emulation done!
RAX: 0x43e
RBX: 0x0
RCX: 0x4
RDX: 0x3
RSI: 0x0
RDI: 0x0
RBP: 0x0
RSP: 0x0
Level 3 successful!
TG20{look_ma_im_a_math_wiz}
```
