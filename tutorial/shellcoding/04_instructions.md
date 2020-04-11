## Instructions
Following is a list of some of the more common instructions you can use.
For more information about instructions, you can use these resources:
* https://en.wikipedia.org/wiki/X86_instruction_listings
* https://www.felixcloutier.com/x86


### add
`add` is used to (you guessed it) add two numbers together. You can use it to
add a value directly to memory or to a register. If the register rax contains
the value `2` and we run the instruction `add rax, 2` we will add `2` to
`rax`, after which `rax` contains `4` (since `2 + 2 = 4`). For `add` to be
useful, you probably have to move some values into the registers you are using
first. In addition to using numbers as the second operand, you can also use
registers.

Let's say that `rax` contains the value `3`, and `rbx` contains `5`. Then, running
`add rax, rbx` will add `5` to `3`, setting `rax` to `8`.

Here are some examples of usage. All the text after `;` are comments in the code
explaining how the registers will look after each instruction has been executed.
```asm
mov    rax, 0x2	; rax = 0x2
mov    rbx, 0x10	; rbx = 0x10
add    rax, 0x12	; add 0x12 to rax, rax = 0x14
add    rbx, rax     ; add rax to rbx. 0x10 + 0x14 = 0x24
```


### sub
`sub`, conversely to `add`, is used to subtract numbers. Here are some examples:

```asm
mov    rax, 0x3    ; rax = 0x3
mov    rbx, 0x5    ; rbx = 0x5
sub    rbx, rax    ; rbx -= rax => rbx = 0x5 - 0x3 = 0x2
```

Let's go through the lines one-by-one. On the first line we set `rax` to `0x3`.
Then we set `rbx` to `0x5`. Finally, we subtract `rax` *from* `rbx`. This sets
`rbx` to `0x5 - 0x3`, which is `0x2`.

### mul
`mul` is used to perform multiplication. Note that the operand is the source
register for `mul`. The destination is implicitly `rax`. Which means that if
you write `mul rbx` you will multiply `rax` with `rbx` and store the result in
`rax`. Following are a few examples:

```asm
mov rax, 0x8		; rax = 0x8
mov rbx, 0x2		; rbx = 0x2
mul rbx		; rax = rax * rbx => rax = 0x2 * 0x8 = 0x10
```

You can also multiply `rax` with itself:
```asm
mov rax, 0x2		; rax = 0x2
mul rax		; rax = rax * rax => 0x2 * 0x2 = 0x4
```

### div
Can you figure out how the `div` instruction works? It might be useful for some
of the challenges coming up :)

## Assembly Code Challenges
Before moving on to look at functions, let's get our hands dirty and do some
challenges! All the challenges are running on the same service, which lets you
choose the level you want to try. Let's take a look at the challenge description
for the first task, Baby's First Assembly Code:
```
Zero out the `rax` register. Which means you have to set `rax` to 0.  That's it!
```

Okay, so the task wants us to set `rax` to zero. Let's connect to the server
using netcat: `nc shellcoding.tghack.no 1111`. You should see a welcome
message, and a question if you want single-step mode or not. Answer `y` to
single-step mode, so that you can see what happens after executing every
assembly instruction.
We can start by sending assembly code to the server that moves some values into
different registers and observing the result.

```console
Welcome!
Do you want single-step mode? (Y/N) y
Level: 1
Please give me some assembly code, end with EOF
mov rbx, 1
mov rdx, 2
mov rdi, 1337
EOF
```
We start by sending some code to the server that sets rbx to 1, rdx to 2, and
rdi to 1337. We end with EOF to tell the server that we are done sending code.
Also note that we enabled single-step mode by sending y, so that we can see the
result of every single instruction. Now press enter a couple of times to execute
the first instruction.

```console
code: mov rbx, 1
mov rdx, 2
mov rdi, 1337

RAX: 0xdeadbeefcafe
RBX: 0x0
RCX: 0x0
RDX: 0x0
RSI: 0x0
RDI: 0x0
RBP: 0x0
RSP: 0x0
0x1000:	mov	rbx, 1
Press enter to step
>
RAX: 0xdeadbeefcafe
RBX: 0x1
RCX: 0x0
RDX: 0x0
RSI: 0x0
RDI: 0x0
RBP: 0x0
RSP: 0x0
0x1007:	mov	rdx, 2
Press enter to step
>
```

After stepping once, we see that rbx has been set to 1. Let's finish stepping
through the code.

```console
RAX: 0xdeadbeefcafe
RBX: 0x1
RCX: 0x0
RDX: 0x2
RSI: 0x0
RDI: 0x0
RBP: 0x0
RSP: 0x0
0x100e:	mov	rdi, 0x539
Press enter to step
>
Emulation done!
RAX: 0xdeadbeefcafe
RBX: 0x1
RCX: 0x0
RDX: 0x2
RSI: 0x0
RDI: 0x539
RBP: 0x0
RSP: 0x0
Level 1 failed!
```
All the registers have been set to the values from our code. However, rax is
still some random looking value. We want it to be zero to get the first flag.

Can you get the flag on your own? Good luck!

---

The next challenge is similar to the first one. This time we have to set up
the registers as follows:

| Register name | Value |
|:-----------:|:---:|
| rax | 42 |
| rbx | 13 |
| rcx | 37 |
| rdi | 0 |
| rsi | 1337 |

You can use the `mov` function like we did in the previous challenge to set up
all the registers. Use the single-step functionality if you are stuck to verify
that the registers are set to the correct values.

---
Now, the next challenge is `Division` (level 3). Let's start by taking a look at
how the `div` instruction works using single-step mode.

```console
$ nc shellcode.tghack.no 1111
Welcome!
Do you want single-step mode? (Y/N) y
Level: 3
Please give me some assembly code, end with EOF
mov rax, 0x40
mov rdi, 0x10
div rdi
EOF
```

For this example, we will calculate `0x40 / 0x10 = 0x4`. Note that we are using
hex numbers since the service dumps the register values as hex. We start by
moving 0x40 into rax. rax is used automatically as the dividend (the number
		being divided) when using the div instruction.

```console
RAX: 0x40
RBX: 0x0
RCX: 0x0
RDX: 0x0
RSI: 0x0
RDI: 0x0
RBP: 0x0
RSP: 0x0
0x1007:	mov	rdi, 0x10
Press enter to step
>
```

Next, we set up the divisor (which is the number we will divide by) in rdi.

```console
RAX: 0x40
RBX: 0x0
RCX: 0x0
RDX: 0x0
RSI: 0x0
RDI: 0x10
RBP: 0x0
RSP: 0x0
0x100e:	div	rdi
Press enter to step
>
```

Lastly we specify the divisor to use with the div instruction. Let's look at the
final result after stepping.
```console
Emulation done!
RAX: 0x4
RBX: 0x0
RCX: 0x0
RDX: 0x0
RSI: 0x0
RDI: 0x10
RBP: 0x0
RSP: 0x0
Level 3 failed!
```
Note that the result of the operation is stored in rax. And as expected, we see
that rax now contains 0x4! The division task asks you to divide rax by 4, how
would you do that?

When you are done with the first three challenges, we can move on to functions!
