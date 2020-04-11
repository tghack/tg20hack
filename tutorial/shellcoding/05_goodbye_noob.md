# Good bye, n00b

In this final part of the n00b shellcoding tutorial we will actually write some
shellcode!

Shellcode has its name from old school exploitation, and the goal of shellcode
is usually to spawn a shell or perform some other useful action to gain control
over a program. Shellcode is usually used when we can inject code into a
program by some means, and we want to gain control of the program. Shellcode is
usually written in assembly since the code is usually quite small. Sometimes
shellcode is written in C, but you have to use some dark magic to make it work.

Sometimes we can write shellcode without any restrictions on size, legal bytes,
and what actions are allowed by the operating system (Linux in our case).
Other times you might have to write shellcode with a very limited size, some
bytes like null bytes might be illegal, or maybe you're only allowed to read
and write data.

To interact with the operating system, we use something known as system calls,
or syscalls for short. Syscalls allow us to open files, read data, start new programs, map memory, and so on. We will discuss some normal syscalls and how to
use them in the following sections. To exit a program, for example, you can
use the `exit` syscall. To find more information about the different syscalls on
Linux, you can use the man pages. Syscalls are documented in section 2, so you
would write `man 2 exit` to view documentation for the `exit` syscall.
Remember the calling convention for functions in the previous section? The
syscall calling convention is similar for the first few arguments. See the
following table for details:

|Register|Usage|
|:--------:|:------:|
|rax|Syscall number|
|rdi|First argument|
|rsi|Second argument|
|rdx|Third argument|
|r10|Fourth argument|
|r8|Fifth argument|
|r9|Sixth argument|

## Syscall Numbers
Every syscall is identified by a number. These numbers vary between different
architectures, but we will only deal with x86_64 for this tutorial. There are
many ways to find the syscall numbers, for example:
* [here](https://filippo.io/linux-syscall-table/)
* looking through header files in /usr/include for `__NR_<syscall name>`
definitions. For example `__NR_read` for the `read` syscall.
* using pwntools

Using `pwntools` is a really convenient way of checking what the syscall numbers
are. In `pwntools` you can get the values by importing everything from `pwn` and
then accessing the values from the `constants` module. The following snippet
shows how you can access these values from `ipython`. You could use this in a
script as well.
```python
In [1]: from pwn import *

In [2]: context.arch
Out[2]: 'i386'

In [3]: context.arch="amd64"

In [4]: constants.SYS_exit
Out[4]: Constant('SYS_exit', 0x3c)
```

Note that you have to set `context.arch` to `amd64` to get the x86_64 syscall
numbers. `i386` will get you the 32-bit syscall numbers instead.

## Baby's First Syscall
Enough talk, let's try to write our first syscall. For this part, we will use
`nasm`, which is a simple assembler that turns assembly source code into
object code. We will also be using another tool called `strace` to see that our
program does what we expect it to do.
To install `nasm` and `strace`, run the following command:
* Ubuntu/Debian: `sudo apt install -y nasm strace`
* Arch: `pacman -S nasm strace`
* Fedora/CentOS: `yum install -y nasm strace`

The following is a skeleton you can use when writing 64-bit assembly code using
nasm:
```asm
[BITS 64]
global _start

_start:
	; ASSEMBLY CODE GOES HERE
```

Comments in nasm start with `;`. For our first syscall, let's look at how we
would call `exit(0)` (that's `exit` with status code 0). Please take a look at
the following assembly code.
```asm
[BITS 64]
global _start

_start:
	; set status code to 0
	; rdi: first argument
	mov		rdi, 0

	; set syscall number to 0x3c => SYS_exit
	mov		rax, 0x3c

	; syscall time!
	syscall
```

Put the code into a file called exit.s, and compile it using the following
commands:

```
$ nasm -felf64 exit.s -o exit.o
$ ld exit.o -o exit
$ file exit
exit: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, not stripped
$ ./exit
```

And nothing happened! That's because our program doesn't really do anything
interesting. It only calls exit and that's it. To verify that our program works
as expected, we can use a tool called `strace`:

```
$ strace ./exit
execve("./exit", ["./exit"], 0x7ffff7fcfa50 /* 63 vars */) = 0
exit(0)                                 = ?
+++ exited with 0 +++
```

At the last line, you see that the program calls `exit(0)` just like we wanted.
Try to change the return code and see what happens when you run the program
with `strace`.


## Final Task
We're almost at the end of the tutorial now, hope you had some fun and learned
some new things! You should be ready to tackle one final challenge before moving
on though! Try to solve the task `Baby's First Shellcode`. Good luck and have fun!


To conclude this tutorial, we will end with a short summary and some tips for
solving the other shellcode tasks.

## Summary
After solving `Baby's First Shellcode`, you should be able to take a look at the
shellcode bootcamp tasks. We learned how to set up registers when issuing
syscalls, how you can find the different syscall numbers (using pwntools).
If you want to write shellcode that uses a specific syscall, you can use the
man pages to find documentation on how the syscall works and what the arguments
should be. Take a look at `man 2 mmap` for example to see how the `mmap`
syscall works.


### Resources
* [shell-storm](http://shell-storm.org/shellcode/)
	* tons of shellcode examples
* [The Shellcoder's Handbook](https://www.wiley.com/en-us/The+Shellcoder%27s+Handbook%3A+Discovering+and+Exploiting+Security+Holes%2C+2nd+Edition-p-9780470080238)
	* old but gold
	* mostly about exploitation, but some cool shellcode tricks
