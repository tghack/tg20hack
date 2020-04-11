# Useless Crap Writeup
**Author: PewZ**

**Difficulty: hard**

**Category: pwn**

---

We are given a binary and a libc. After some basic reverse engineering, we get
an idea of what the binary is doing. First, it uses seccomp to set up a sandbox,
filtering out unwanted syscalls. Then, we can either read or write from/to
arbitrary memory addresses. However, we are only allowed to read/write twice!

In addition, we can leave feedback, but we're only allowed to do so once. We can
also read it back afterwards.

Let's take a look at the seccomp filter using
[seccomp-tools](https://github.com/david942j/seccomp-tools):
```console
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x12 0xc000003e  if (A != ARCH_X86_64) goto 0020
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x0f 0xffffffff  if (A != 0xffffffff) goto 0020
 0005: 0x15 0x0d 0x00 0x00000002  if (A == open) goto 0019
 0006: 0x15 0x0c 0x00 0x00000003  if (A == close) goto 0019
 0007: 0x15 0x0b 0x00 0x0000000a  if (A == mprotect) goto 0019
 0008: 0x15 0x0a 0x00 0x000000e7  if (A == exit_group) goto 0019
 0009: 0x15 0x00 0x04 0x00000000  if (A != read) goto 0014
 0010: 0x20 0x00 0x00 0x00000014  A = fd >> 32 # read(fd, buf, count)
 0011: 0x15 0x00 0x08 0x00000000  if (A != 0x0) goto 0020
 0012: 0x20 0x00 0x00 0x00000010  A = fd # read(fd, buf, count)
 0013: 0x15 0x05 0x06 0x00000000  if (A == 0x0) goto 0019 else goto 0020
 0014: 0x15 0x00 0x05 0x00000001  if (A != write) goto 0020
 0015: 0x20 0x00 0x00 0x00000014  A = fd >> 32 # write(fd, buf, count)
 0016: 0x15 0x00 0x03 0x00000000  if (A != 0x0) goto 0020
 0017: 0x20 0x00 0x00 0x00000010  A = fd # write(fd, buf, count)
 0018: 0x15 0x00 0x01 0x00000001  if (A != 0x1) goto 0020
 0019: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0020: 0x06 0x00 0x00 0x00000000  return KILL
```
Here's the gist:
* we can only use `open`, `close`, `read`, `write`, `mprotect`, and `exit_group`
  syscalls, and
* only read from fd 0 (stdin), and
* only write to fd 1 (stdout)

We have to keep this in mind for later.

The binary is a PIE and there's no free info leak, so we need to find a way to
get a memory leak. If we look at the size of the feedback, we see that it is
`0x500`, which is large enough not to end up in the tcache bins.

The functions to leave feedback looks something like this:
```C
static void leave_feedback(void)
{
	char c;

	if (feedback) {
		puts("that's enough feedback for one day...");
		return;
	}

	feedback = calloc(1, 0x501);

	printf("feedback: ");
	if (!fgets(feedback, 0x500, stdin))
		exit(EXIT_FAILURE);

	printf("you entered: %s\n", feedback);
	puts("Do you want to keep your feedback? (y/n)");

	c = getchar();
	if (c == 'y')
		return;
	else if (c == 'n')
		free(feedback);
}
```

If we answer no to keeping the feedback, the pointer is freed. It is not set to
`NULL`, however. Which means that we have a UAF when reading the feedback. When
freeing the heap chunk, its `fd` pointer will point into the libc, giving us an
information leak.

So now we know the libc base address, but what's next? Since the program only allows
us to read and write once, we should probably figure out a way to bypass this
restriction. Looking closely at the read/write checks we can see that a signed
comparison is performed, which means that the check will pass as long as the
count is set to a negative number.

To set these to a negative number we first need to leak the address of our
binary. By quickly glancing through libc and the other loaded libraries, a
pointer to our binary was found inside ld-linux at `_dl_rtld_libname`. The
libraries are loaded with the same distance between them for each run, so we can
calculate the offset between `_dl_rtld_libname` and the libc base address and
use it for each exploit attempt.

After leaking the binary base we can overwrite the read/write count in one go at
offset `0x202030` since both of them are 4-byte integers. After overwriting
these values we can read and write as much as we want!


For the exploitation part, we choose the following gadget in `setcontext()` that
can be used to pivot the stack:
```
.text:0000000000045BA5                 mov     rsp, [rdx+0A0h]
.text:0000000000045BAC                 mov     rbx, [rdx+80h]
.text:0000000000045BB3                 mov     rbp, [rdx+78h]
.text:0000000000045BB7                 mov     r12, [rdx+48h]
.text:0000000000045BBB                 mov     r13, [rdx+50h]
.text:0000000000045BBF                 mov     r14, [rdx+58h]
.text:0000000000045BC3                 mov     r15, [rdx+60h]
.text:0000000000045BC7                 mov     rcx, [rdx+0A8h]
.text:0000000000045BCE                 push    rcx
.text:0000000000045BCF                 mov     rsi, [rdx+70h]
.text:0000000000045BD3                 mov     rdi, [rdx+68h]
.text:0000000000045BD7                 mov     rcx, [rdx+98h]
.text:0000000000045BDE                 mov     r8, [rdx+28h]
.text:0000000000045BE2                 mov     r9, [rdx+30h]
.text:0000000000045BE6                 mov     rdx, [rdx+88h]
.text:0000000000045BE6 ; } // starts at 45B70
.text:0000000000045BED ; __unwind {
.text:0000000000045BED                 xor     eax, eax
.text:0000000000045BEF                 retn
```
As long as we control `rdx`, we can also control `rsp` :)

But how do we trigger execution of that gadget while `rdx` is controlled? We use
a trick similar to [this
one](https://dhavalkapil.com/blogs/FILE-Structure-Exploitation/). When the
program calls `exit()` it calls some exit handlers. Among these are
`_IO_cleanup()` which calls `_IO_flush_all_lockp()` to flush all the data
remaining in stdout and friends. If certain conditions are met, the
`_IO_OVERFLOW` macro is used to call the overflow function in the `FILE`'s
vtable. On the libc version used the vtables are read-only, but we can still
change the vtable pointer inside a `FILE`. We create a fake file that meets the
conditions for calling the overflow function and modify the vtable so that it
calls `_IO_str_overflow()` instead of the original overflow function.
`_IO_str_overflow()` calls `malloc()` if the conditions mentioned in the blog
post above are met. We can basically choose to control rdi or rdx, which is
perfect for the gadget we are using.

Finally we overwrite `__malloc_hook` with the stack pivot gadget and write a ROP
chain to the binary's bss. The ROP chain calls `mprotect()` on the stack to make
it rwx and then reads more shellcode there, this shellcode opens, reads, and
writes the file.

1. leak libc through UAF
2. leak binary base through `_dl_rtld_libname`
3. get arbitrary read/write by overwriting count variables
4. leak stack
5. create fake `FILE`
6. overwrite `_IO_list_all` with our fake `FILE`
7. overwrite `__malloc_hook` with stack pivot gadget
8. place ROP chain in bss
9. trigger ROP chain through `exit()` -> `_IO_flush_all_lockp()` ->
   `_IO_str_overflow()` -> `malloc()`
10. shellcode prints the flag

See the [solution script](./src/solve.py) for more details.

```console
$ python2 solve.py REMOTE
[*] libc leak: 0x7fb4a231dbe0
[+] libc base: 0x7fb4a1f68000
[*] _dl_rtld_libname: 0x7fb4a2793050
[*] binary leak: 0x55d7213fc238
[+] binary base: 0x55d7213fc000
[*] stack: 0x7ffe2830b758
[*] stdin: 0x7fb4a231d980
[*] scratch: 0x55d7215fe100
[*] pivot at 0x7fb4a1fadba5
[*] Switching to interactive mode
1. read
2. write
3. exit
> TG20{thank_you_for_pwning_this_binary_and_have_a_nice_day}
```
