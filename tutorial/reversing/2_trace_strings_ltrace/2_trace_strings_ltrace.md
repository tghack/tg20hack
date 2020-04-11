# Combat Ship Reversing Exercise 2: Tracing strings with ltrace

In this class of Combat Ship Reverse Engineering, we are going to dive into
how we may trace a program's flow and find `if statements`. We start this class
by explaining what `if statements` are, and then we experience some if 
statements through dynamic reverse engineering with `ltrace`.

You will learn how to find a program's expected input, in order to enter the
correct answer of all the questions. Wrong answers make the program exit,
so it is crucial to enter the right answers to let the program continue until 
the flag is printed. 

Before starting with the actual reverse engineering, you should know what 
`if statements` are. It is also nice to know what the `strcmp()` function does.
If you know what both of those are, you may skip the following section. 

## If statements
In computer science, we have something called `conditional statements`. When 
developers are coding, they often have the need of doing an action based on the
value of a _variable_. That means they have to see whether the variable contains
a certain value or not. In these cases `if statements` are commonly used. 

<details>
<summary>Protip!</summary><p>

Remember to google any terms that are new to you! If you are stuck, make sure 
to ask @tghack in the Discord channel. You may find the information at the 
Contact page.
</p></details>

An `if statement` in the C programming language looks like the following snippet:
```C
1 if (strcmp(some_variable, another_variable) == 0) {
2 	 printf("The variables are alike!");
3 } else {
4 	 printf("The variables are not alike...");
5 }
```

* Line 1: At the beginning of this line, we see the term `if`. This is what makes
the interpreter of the code understand what to do next. Next, we see that 
there are two parantheses with some content inside. This content must be a
conditional statement. A conditional statement return a boolean value. 
A boolean value is either `true` or `false`. In this case, the conditional 
statement checks if the results of the function called `strcmp` equals to zero.
The function `strcmp` compares whether two pieces of text are equal or not. 
It returns `0` if they are equal. Therefore, the conditional statement returns
`true` if the pieces of text are equal. Read more about `strcmp` and `boolean
expressions` in the following drop downs.
* Line 2: The `printf` function is run with a piece of text inside. All 
the function does is to print the text in the terminal. No hocus pocus. 
However, this is only printed if the conditional statement returns `true`.
* Line 3: This line has some curly brackets with just a single word inbetween, 
`else`. Whatever is written in between the curly brackets after this statement
is executed if the conditional statement returns `false`.
* Line 4: Just like in line 2, the printf function is run, which prints a 
piece of text to the terminal. This `printf` is called if the conditional 
statement returns `false`.
* Line 5: A curly bracket ending the if statement. Each curly opening curly 
bracket always has an ending curly bracket in programming. 

So all these lines result in a flow that starts by checking if an boolean
expression returns `true` or `false`. If it returns true, then the `printf` at
line 2 is executed, if it returns false, the `printf` at line 4 is executed. 

<details>
<summary>Let's play a short game of "Guess the if statement result"!</summary><p>

To illustrate further, let's play a game. We have two variables, `some_variable`
and `another_variable`. Let's check two different scenarios, and see whether
you get the correct answer:

**Scenario 1**

```C
char *some_variable = "This is some random variable";
char *another_variable = "This is another random variable";

if (strcmp(some_variable, another_variable) == 0) {
	 printf("The starfleet suits look so good.");
} else {
	 printf("The starfleet suits are super popular.");
}
```

**Scenario 2**

```C
char *some_variable = "This is some random variable";
char *another_variable = "This is some random variable";

if (strcmp(some_variable, another_variable) == 0) {
	printf("Starfleets are cool :)");
} else {
	printf("Starfleets are very huge.");
}
```

**Correct answers**

The if statement in scenario 1 prints the sentence "The starfleet suits are 
super popular." because the boolean expression returns false. 

The if statement in scenario 2 prints the sentence "Starfleets are cool :)" 
because the statement returns true. 

If you don't understand why the statement returns true or false, please read 
the dropdown below, or google how the `strcmp` function works. 

</p></details>

<details>
<summary>What is strcmp()?</summary><p>

`strcmp` is a function commonly used in C programming to compare to strings. 

This is the declaration of the function:
```C
int strcmp(const char *str1, const char *str2)
```

This means that it returns an `int`, which is short for `integer` and means a
number. And then it takes two char pointers as input. Char pointers are the
same as strings in other programming languages. 

The function return:
* 0 if _str1_ and _str2_ are equal.
* a number bigger than 0 (return_value > 0) if _str2_ is less than _str1_.
* a number lower than 0 (return_value < 0) if _str1_ is less than _str2_.

This is the reason why we checked whether the `strcmp` function returned `0` in
the if statement above.

Read more about strcmp() by using the man pages (`man strcmp` in the terminal),
or [at this page](https://www.tutorialspoint.com/c_standard_library/c_function_strcmp).
</p></details>

<details>
<summary>What is a boolean expression?</summary><p>

As stated in 
[this Oracle documentation](https://docs.oracle.com/cd/B12037_01/olap.101/b10339/expression006.htm):
```
A boolean expression is a logical statement that is either TRUE or FALSE. 
Boolean expressions can compare data of any type as long as both parts of 
the expression have the same basic data type. You can test data to see if
it is equal to, greater than, or less than other data. 
```

Let's see a few examples. If we have two variables, `a` and `b`, and a boolean 
expression. What will the result be? `true` or `false`?

**Example 1**
```
int a = 15;
int b = 10;

bool result = a == b;
```

**Example 2**
```
int a = 15;
int b = 10;

bool result = a > b;
```

**Example 3**
```
int a = 15;
int b = 10;

bool result = a < b;
```

**Results**

* **1: false**, because the logical operator checks whether the integer (number) 
values are the same
* **2: true**, because the logical operator checks if `a` is bigger than `b`,
and indeed `15` is a bigger number than `10`.
* **3: false**, because the logical operator checks if `a` is bigger than `b`.
`15` is not smaller than `10`, so this logical expression is false. 

Note that these examples only work in C if you include the library called 
`stdbool.h`. That is because the `bool` data type is not a part of the standard
C library, and using the data type without the library will not work. 

</p></details>

## Let's get our hands dirty!
Alright, time to start with the reversing! At first, we need to fetch the 
binary file: 

* [Combat Ship Reversing Exam 2 binary](re_noob)

We have put loads of random strings into the binary to make it too hard for you
to use `strings` like you did in te previous challenge. Time to learn another 
technique!

### Tracing with "ltrace"
Let's solve the challenge using another, quicker tool: `ltrace`. The `ltrace` 
description from the [online Linux man page](https://linux.die.net/man/1/ltrace):
```
ltrace is a program that simply runs the specified command until it exits. 
It intercepts and records the dynamic library calls which are called by 
the executed process and the signals which are received by that process. 
It can also intercept and print the system calls executed by the program.
```

To understand this description, we need to understand what a dynamic library 
call is, what a process is and what signals which are received by a process are. 
A dynamic library is a collection of code that is loaded when the program is
executed. Dynamic libraries contain commonly used code, e.g. code to read files,
or to print into the terminal. A process is a running program. So let's say you
run the combat ship program five times at the same time. Then you have five
processes running on your machine. Or, at least five processes, as you 
have may other processes running. E.g. Chrome and Spotify. We don't think it 
is necessary to discuss signals in this
tutorial, but of course, you should google it if you are curious! 

But how does `ltrace` affect us? When we run our combat ship binary using 
`ltrace`, we get to see which functions from the dynamic library are called. 
Let us just test it out. Learning by doing!

Start by running `ltrace` with the binary:
```bash
$ ltrace ./re_noob2 
puts("Welcome to the Combat Ship softw"...Welcome to the Combat Ship software...
) = 39
puts("Please answer a few questions to"...Please answer a few questions to access the system.
) = 52
puts("Give me the captain's name?"Give me the captain's name?
)         = 28
fgets(
```
Are you starting to get it? The dynamic function calls here are `puts()` and
`fgets()`. It currently stopped at `fgets()`, waiting for some input from the
terminal. You may google or man page these functions. 

As the terminal is now waiting for some input, try inserting something random, 
and press enter. In the following example, we inserted `asd`:
```bash
$ ltrace ./re_noob2 
puts("Welcome to the Combat Ship softw"...Welcome to the Combat Ship software...
) = 39
puts("Please answer a few questions to"...Please answer a few questions to access the system.
) = 52
puts("Give me the captain's name?"Give me the captain's name?
)         = 28
fgets(asdfasf
"asdfasf\n", 50, 0x7ff8183eba00)           = 0x7ffd97aa6570
strcspn("asdfasf\n", "\n")                       = 7
strcmp("asdfasf", "Captain bolbz")               = 30
exit(1 <no return ...>
+++ exited (status 1) +++
➜  uploads git:(noob-re-ch
```

Cool. We see some new function calls from the dynamic library, `strcpsn()`, 
`strcmp()` and `exit()`. 

Now, by reading the third bottom line, we see that our input is compared
with the string `Captain bolbz`. That means that `Captain bolbz` is the right 
answer! Run ltrace again and insert the right answer:
```bash
ltrace ./re_noob2
puts("Welcome to the Combat Ship softw"...Welcome to the Combat Ship software...
) = 39
puts("Please answer a few questions to"...Please answer a few questions to access the system.
) = 52
puts("Give me the captain's name?"Give me the captain's name?
	)         = 28
fgets(Captain bolbz
"Captain bolbz\n", 50, 0x7ff274bb6a00)     = 0x7fff3feebda0
strcspn("Captain bolbz\n", "\n")                 = 13
strcmp("Captain bolbz", "Captain bolbz")         = 0
puts("How much starpower does the Star"...How much starpower does the Starfleet have?
)      = 44
fgets(
```

Okay, the binary is waiting for input yet another time. Repeat this process 
until you get the flag!

Note that some binary files will not allow `ltrace`, which you will experience
in the next tutorial!

## Summary
In this class, you have learned how to find your way through different
flows of a program by doing dynamic reverse engineering with `ltrace`. By 
following the tutorial, you should have obtained the flag for the following 
reverse engineering challenge:

* [Combat Ship Reversing Exam 2: Tracing](link.til.oppgave)

