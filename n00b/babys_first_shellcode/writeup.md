# Baby's First Shellcode writeup
**Author: PewZ**

**Difficulty: n00b**

**Category: n00b**

---

Now we're talking! Time to write some shellcode. Syscall numbers are placed
in `rax` and the first argument is placed in `rdi`.
First we need to find the syscall number of `exit`. One way to accomplish this
is to use `pwntools`. Note that we have to set the correct architecture since
it defaults to 32-bit x86.
```console
$ ipython
Python 2.7.15+ (default, Oct  7 2019, 17:39:04)
Type "copyright", "credits" or "license" for more information.

IPython 5.5.0 -- An enhanced Interactive Python.
?         -> Introduction and overview of IPython's features.
%quickref -> Quick reference.
help      -> Python's own help system.
object?   -> Details about 'object', use 'object??' for extra details.

In [1]: from pwn import *

In [2]: context.arch="amd64"

In [3]: constants.SYS_exit
Out[3]: Constant('SYS_exit', 0x3c)

In [4]: 0x3c
Out[4]: 60
```

Okay, so the value for the exit syscall is `60`. We move that into `rax` and
the desired return value, which is `42`, into `rdi`. Lastly we use the
`syscall` instruction to actually perform the syscall.

```asm
	mov rdi, 42
	mov rax, 60
	syscall
```

```console
$ nc shellcode.tghack.no 1111
Welcome!
Do you want single-step mode? (Y/N) n
Level: 7
Please give me some assembly code, end with EOF
mov rdi, 42
mov rax, 60
syscall
EOF
code: mov rdi, 42
mov rax, 60
syscall

0x1000:	mov	rdi, 0x2a
0x1007:	mov	rax, 0x3c
0x100e:	syscall
stopping emulation!
Emulation done!
RAX: 0x3c
RBX: 0x0
RCX: 0x0
RDX: 0x0
RSI: 0x0
RDI: 0x2a
RBP: 0x0
RSP: 0x0
Level 7 successful!
TG20{good_bye_noob_hello_shellcode}
```
