## Functions
Functions can be quite complicated, as we often have to deal with something
called the stack, which is a last-in-first-out (LIFO) structure used to
store values. To learn more about the stack, you can take a look at the
[pwntions tutorial](https://19.tghack.no/page/Pwntions%20tutorial) from TG:Hack
2019.

For this tutorial, we skip all details surrounding the stack, but it's nice
to have heard of the term, as it plays a big part when calling functions. The
program will use the stack to figure out where to return after running a
function, for example.

Consider the following C function:
	```C
int func(void)
{
	return 1337;
}
```

This is a function that returns an `int` and has no parameters. How would this
function look like in assembly?

```asm
func:
mov    rax, 1337
ret
```

The return value is stored in `rax`, and we use a label to
refer to the function. The label can be named anything, for example `func` in
the snippet above. Calling a function in C looks like this:

```C
int value = func();
```
After calling the function, the variable `value` contains 1337.

In assembly, it will look like this:
```asm
call    func
```

That's it! The return value is now stored in `rax`.
It gets a bit more complicated when we're dealing with functions with
parameters. On 64-bit x86, parameters are passed in registers. How we use the
registers is called the
[calling convention](https://en.wikipedia.org/wiki/X86_calling_conventions).
We will use the calling convention that is standard for all Unix-like operating
systems (like Linux, BSD, etc.). In this calling convention, arguments are
passed in the following registers: `rdi`, `rsi`, `rdx`, `rcx`, `r8`, and `r9`.

The first parameter is stored in `rdi`, the second in `rsi`, and so on.

Let's take a look at functions with parameters, and how to call them. First in
C:
	```C
int func(int a)
{
	return a * 2;
}

int main(void)
{
	int b = func(42);
	// b now contains 84

	return 0;
}
```

And now in assembly:
```asm
main:
mov    rdi, 42
call   func
ret

func:
mov    rax, rdi
mul    rax, 2
ret
```

Let's start by looking at what `func` does. The first parameter (in `rdi`) is
moved into `rax`. `rax` is then multiplied by 2 and returned using the `ret`
instruction.
Inside `main`, 42 is first moved into `rdi`. This will be the argument to
`func`. `func` is called using the `call` instruction, and afterwards we simply
return from main, as the value isn't used anywhere. `main` will end up returning
84 though, since `rax` is set to `42 * 2` by `func`.


## Function Challenges
Ready for some challenges related to functions? Let's go!

First of all, to connect to the service you can use netcat (the `nc` command).
The service is running on `shellcode.tghack.no`, port `1111`. When you connect,
you will be greeted with a welcome message, and a question of whether you want
to enable single-step mode or not. Single-step mode allows you to step through
every single assembly instruction you send to the server. So this can be
helpful when debugging your code. You also have to choose a level when
connecting. Choose the appropriate level based on what challenge you are
currently solving. The tutorial will show you the correct level, so if you are
following that closely you can rely on those level numbers. The server will read
your assembly code line-by-line and stop reading when you send `EOF` (end of
file). After sending your code, the server will either let you single-step
through the code, or run everything and print the result. If everything went as
planned, you will get a flag :)

The first challenge is the following:
```
Create a function that takes no parameters and returns 0.
You only have to write the function body.
```

We will use a slightly more complicated example here, to not spoil the solution
right away. Please note that you do not have to send the name of the function,
like in the example in the previous section. You only have to send the function
body, ending it with a `ret` instruction. 

```console
$ nc shellcode.tghack.no 1111
Welcome!
Do you want single-step mode? (Y/N) y
Level: 4
Please give me some assembly code, end with EOF
mov rdi, 0x1337
mov rax, 0x41414141
ret
EOF
code:
call    func
ret
func:
mov rdi, 0x1337
mov rax, 0x41414141
ret
```

Note the code section that shows up after EOF.
The code looks like this:

```console
call    func
ret

func:
mov rdi, 0x1337
mov rax, 0x41414141
ret
```
At the top there's a call instruction that calls a function named `func`. This
function contains the code that we sent to the service.

When we single-step, we start off inside the function:
```console
RAX: 0xdeadbeefcafe
RBX: 0x0
RCX: 0x0
RDX: 0x0
RSI: 0x0
RDI: 0x0
RBP: 0x0
RSP: 0x200ff8
0x1006:	mov	rdi, 0x1337
Press enter to step
>
```

Let's step out and look at the final result:
```console
RAX: 0xdeadbeefcafe
RBX: 0x0
RCX: 0x0
RDX: 0x0
RSI: 0x0
RDI: 0x1337
RBP: 0x0
RSP: 0x200ff8
0x100d:	mov	rax, 0x41414141
Press enter to step
>
RAX: 0x41414141
RBX: 0x0
RCX: 0x0
RDX: 0x0
RSI: 0x0
RDI: 0x1337
RBP: 0x0
RSP: 0x200ff8
0x1014:	ret
Press enter to step
>
Emulation done!
RAX: 0x41414141
RBX: 0x0
RCX: 0x0
RDX: 0x0
RSI: 0x0
RDI: 0x1337
RBP: 0x0
RSP: 0x201000

Level 4 failed!
```

rax contains 0x41414141, which isn't the correct return value for this level.
Can you make the function return 0 and get the flag?

---

The next challenge is `Function Parameters` and it's a bit more tricky than the
previous challenges. Let's look at the challenge description:

```
Create a function that takes one parameter, a, and returns (a * 4) + 3.
```

Okay, so first of all we need to handle function parameters. The first parameter
is passed in rdi, so we access the parameter through that register.
Next, we multiply it by 4. Just like the `div` instruciton, `mul` will
implicitly use rax. We can start by only doing the multiplication:

Tip: You can refer back to the previous chapter to see how the `mul`
instruction works.

```console
Welcome!
Do you want single-step mode? (Y/N) y
Level: 5
Please give me some assembly code, end with EOF
mov rax, rdi
mov rdi, 4
mul rdi
ret
EOF
code:
push    195939070
mov     rdi, 111
call    func
ret
func:
mov rax, rdi
mov rdi, 4
mul rdi
ret

RAX: 0xdeadbeefcafe
RBX: 0x0
RCX: 0x0
RDX: 0x0
RSI: 0x0
RDI: 0x6f
RBP: 0x0
RSP: 0x200ff0
0x1012:	mov	rax, rdi
Press enter to step
>
```

We move the parameter into `rax`, then move 4 into `rdi`. We then calculate
`rax * rdi` using `mul rdi`. Let's step through and see what happens:

```console
RAX: 0x6f
RBX: 0x0
RCX: 0x0
RDX: 0x0
RSI: 0x0
RDI: 0x6f
RBP: 0x0
RSP: 0x200ff0
0x1015:	mov	rdi, 4
Press enter to step
>
RAX: 0x6f
RBX: 0x0
RCX: 0x0
RDX: 0x0
RSI: 0x0
RDI: 0x4
RBP: 0x0
RSP: 0x200ff0
0x101c:	mul	rdi
Press enter to step
>
RAX: 0x1bc
RBX: 0x0
RCX: 0x0
RDX: 0x0
RSI: 0x0
RDI: 0x4
RBP: 0x0
RSP: 0x200ff0
0x101f:	ret
Press enter to step
>
RAX: 0x1bc
RBX: 0x0
RCX: 0x0
RDX: 0x0
RSI: 0x0
RDI: 0x4
RBP: 0x0
RSP: 0x200ff8
0x1011:	ret
Press enter to step
>
Emulation done!
RAX: 0x1bc
RBX: 0x0
RCX: 0x0
RDX: 0x0
RSI: 0x0
RDI: 0x4
RBP: 0x0
RSP: 0x201000
Level 5 failed!
```

The service places a random value in `rdi` every time, so it might look
different for you. After running the `mul` instruction, `rax` contains `0x1bc`
which is the correct value for `0x6f * 4`.
The final step is to add 3 to `rax` before returning. Can you get the flag on
your own?

---

Before leaving the section on functions we have one more challenge for you!
Can you handle more than one parameter? Check out the challenge called
`More Parameters`. The description is as follows:
```
Create a function that takes two parameters, multiplies them together and
returns the result.
```

The first two parameters are passed in `rdi` and `rsi`. Let's look at an example
where we add the two parameters together instead.

Tip: You can take a look at the previous chapter to see how the `add` and `mul`
instructions work.

```console
Welcome!
Do you want single-step mode? (Y/N) y
Level: 6
Please give me some assembly code, end with EOF
mov rax, rdi
add rax, rsi
ret
EOF
code: 
push    195939070
mov     rdi, 1623
mov     rsi, 4198
call    func
ret
func:
mov rax, rdi
add rax, rsi
ret

RAX: 0xdeadbeefcafe
RBX: 0x0
RCX: 0x0
RDX: 0x0
RSI: 0x1066
RDI: 0x657
RBP: 0x0
RSP: 0x200ff0
0x1019:	mov	rax, rdi
Press enter to step
```
Just like the previous challenge, the parameters will be random, so they change
every time you connect to the service.
We start by moving the first parameter into `rax`, then we add `rsi` to `rax`
and return. Pretty simple, right? Let's step through the function and see how
it looks:

```console
RAX: 0x657
RBX: 0x0
RCX: 0x0
RDX: 0x0
RSI: 0x1066
RDI: 0x657
RBP: 0x0
RSP: 0x200ff0
0x101c:	add	rax, rsi
Press enter to step
>
RAX: 0x16bd
RBX: 0x0
RCX: 0x0
RDX: 0x0
RSI: 0x1066
RDI: 0x657
RBP: 0x0
RSP: 0x200ff0
0x101f:	ret
Press enter to step
>
RAX: 0x16bd
RBX: 0x0
RCX: 0x0
RDX: 0x0
RSI: 0x1066
RDI: 0x657
RBP: 0x0
RSP: 0x200ff8
0x1018:	ret
Press enter to step
>
Emulation done!
RAX: 0x16bd
RBX: 0x0
RCX: 0x0
RDX: 0x0
RSI: 0x1066
RDI: 0x657
RBP: 0x0
RSP: 0x201000
Level 6 failed!
```
After the first step, `rax` contains the same value as `rdi`, which is `0x657`.
Then, we `add` `rsi` to `rax`: `0x657 + 0x1066 = 0x16bd`. And finally we return
from the function. The level fails though, since we are using addition instead
of multiplication. Can you change the function to use multiplication instead?


## Challenge Summary
Following is a list of all the challenges related to this tutorial.

* [Baby's First Assembly Code](link.to.babys_first_asm.task)
* [Registers Everywhere](link.to.registers.task)
* [Division](link.to.division.task)
* [Introduction to Functions](link.to.function.task)
* [Function Parameters](link.to.param.task)
* [More Parameters](link.to.more.params.task)


Don't hesitate to ask questions on Discord or directly to the TG:Hack staff if
you are stuck or have any questions.
