# Assembly Language
In this part of the programme, we will try to get acquainted with assembly and
write a few tiny programs in it. Assembly language can be a bit intimidating at
first, but don't give up! Both assembly language and reverse engineering in
general requires a lot of practice, so it is recommended to try writing some
assembly on your own, in addition to solving the challenges and following the
examples in this programme.


## Assembly Introduction
Assembly language is basically just a wrapper on top of *machine code*.
Machine code is a binary representation of the code that the CPU understands.
Remembering this binary representation would be extremely tedious. A binary
representation is written in only 1's and 0's. So if you were to look at a
binary implementation it could look something like this:
`00011010101011010110111110000111`.  Which is why we write in assembly language
instead.

Different types of computers may have different assembly languages. Each type of
assembly language has different sets of *mnemonics*. A mnemonic is some sort of
device, like letters or numbers, designed to help you remember something. In
assembly language an example of a mnemonic is `ret` used to describe the 
return instruction. In the type of machine code that we will be using, this is
represented using the hex value `0xc3`, which would be very tedious and
difficult to remember. Instruction mnemonics are often an abbreviation of
what the instruction does, for example `mov` for `move`, `sub` for `subtract`,
`div` for `divide`, and so on.

Assembly language is translated into machine code using something called an
*assembler*. In this programme, you can send your assembly code directly to our
servers. Our servers will read your assembly code and check if it is correct. If
you want to test the programs on your own computer, you can use your favourite
assembler. For example `nasm` or `as`. Setting up and using an assembler will
vary between different Linux distributions and operating systems. To keep it
simple, we will not go through how to set up these tools locally. However, we
recommend that you give it a try if you want to learn more!

As mentioned, different types of computers may have different assembly
languages. Assembly language is closely tied to the architecture you are working
with.  There are many different architectures to choose from, but we will focus
on x86_64, which is the most common architecture found in laptops and desktops
today. Many other architectures exist, your phone is probably running on
[ARM](https://en.wikipedia.org/wiki/ARM_architecture), and your router may be
running on [MIPS](https://en.wikipedia.org/wiki/MIPS_architecture).


### x86_64
The architecture we are using is known as x86_64 or amd64. It is a 64-bit
architecture, which basically means that it works with 64-bit registers and
memory addresses. It is a very common architecture for desktop computers,
servers, and laptops. x86_64 has a complex instruction set with many specialized
instructions. For this programme, we only deal with the simpler and more common
instructions, but x86_64 has support for encryption/decryption, specialized
instructions for configuring the CPU, working with large amounts of data at
the same time, and so on.


### Assembly Code Examples
Assembly code may look different depending on what syntax style you are looking
at. Many tools that are relevant for CTFs use a syntax known as Intel syntax,
which is why we will use that style in this tutorial as well. Another popular
style is AT&T syntax. We will not go into the differences between these, but if
you are interested you can see a comparison
 on the [Wikipedia page about X86 assembly](https://en.wikipedia.org/wiki/X86_assembly_language#Syntax).

Let us start easy, and take a look at the following simple assembly language
example:
```asm
mov		rax, 1337
```

Alright, so obviously assembly may seem strange and scary for starship cadets of
all ages. Let us take one step at the time, and start by 
looking at the mnemonic `mov`. Mnemonics like these are called **instructions**. 
Every operation in assembly is controlled using an instruction. You can look at
instructions as the building blocks of the language. Some common operations
carried out by instructions include addition, subtraction, multiplication,
division and `mov`ing values around. There are also many more advanced
instructions for performing
[cryptographic operations](https://www.felixcloutier.com/x86/aesenc) and other
low-level black magic.

The second part of the snippet, `rax, 1337`, are the operands of the `mov`
instruction. `mov` instructions have two operands, a destination operand and a
source operand. For the example above, `rax` is the *destination* operand, and
`1337` is the source operand. Makes sense? `1337` is moved into `rax`, the
destination.

In assembly, we use *registers* to store variables. In x86_64,
we have the following registers (plus a few more that we don't need to know for
this tutorial): `rax`, `rbx`, `rcx`, `rdx`, `rsi`, `rdi`, `rbp`, `rsp`, `rip`.

Ok, we have talked a little about instructions, operands and registers. Now, lets 
continue with the above assembly snippet. The snippet `mov`es the value `1337` 
into the register `rax`. And that's it! This is similar to writing `rax = 1337`
in a high-level language. Although we won't look much into it in this tutorial,
the registers are made up of smaller parts. `rax` is a 64-bit register, but you
can also access the lower 32 bits through the register `eax`. In addition, you
can access the lower 16 bits through `ax`. Finally, you can access the highest
8 bits of `ax` through `ah`, and the lower `8` bits of `ax` through `al`. You
can see the register layout in the table below.

```
+--------------------------------------+
|                 rax                  |	64 bit
+------------------+-------------------+
|                  |        eax        |	32 bit
+----------------------------+---------+
|                  |         |    ax   |	16 bit
+---------------------------------+----+
|                  |         | ah | al |	8 bit
+------------------+---------+----+----+
```
