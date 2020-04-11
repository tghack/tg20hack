# Parallel Universe: Warmup
**Author: PewZ**

**Difficulty: easy**

**Category: pwn**

---

Can you create shellcode that runs on x86 and x86_64 simultaneously?
Read the flag in `flag.txt`.
The following syscalls are allowed:
* `open`
* `read`
* `write`
* `close`
* `exit_group`
* `mmap`

`nc parallel.tghack.no 6004`

or use a mirror closer to you:
* `nc us.parallel.tghack.no 6005 (US)`
* `nc asia.parallel.tghack.no 6005 (Japan)`

The binaries used on the remote side are provided for convenience:
* [pwnme32](uploads/pwnme32)
* [pwnme64](uploads/pwnme64)

Some clarifications:
* you have to use the same number of syscalls for both architectures
* they have to output the same amount of bytes
* you have to use the same syscalls for both architectures
