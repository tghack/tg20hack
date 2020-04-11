# Stronger cryptography

The shift cipher we saw in the previous tutorial is not used to secure
information anymore. This is because it does not provide the cryptographic
security required by today's systems. Simply put, it is easy to break shift
ciphers. XOR cipher is harder to break, and encrypted messages will remain
secret longer with this method.

XOR cipher uses a secret piece of text, which we call the *key*. This key can
be used to "lock" a message that we want to keep hidden, like when you lock
your front door to keep people out. One big difference between door locks and
cryptography, though, is that just having the key is not always enough: you
sometimes also need to know **how the lock itself works**, because there are
infinitely many ways of encrypting data.

The keys in the previous tutorial were numbers, indicating a shift in the
alphabet. If you know the encrypted message is `rflnh`, and you know the key is
`5`, you still need to know that the "lock" is the shift cipher.  This time we
are switching out the lock with something we call XOR'ing, which is harder to
break than shift cipher. It is built on a simple mathematical function, the one
that gives it its name.

> When we say that one encryption algorithm is harder or stronger than another
> one, we generally mean that it takes more time and/or computing power to
> recover the message *when we don't know the key or the message*, even if the
> steps for doing so may be simple.

In mathematics, a function is simply a mapping from input values to output
values. The function plus (`+`) accepts two numbers as input and yields the sum
of those *arguments*. `XOR` is like `plus` in the way that it accepts two input
values, and produces a single output value. The mapping rule for XOR is
relatively simple: if both arguments are the same, the answer is `0`, and if
they are different, the answer is `1`.

| A | B | F |
|---|---|---|
| 0 | 0 | 0 |
| 0 | 1 | 1 |
| 1 | 0 | 1 |
| 1 | 1 | 0 |

The above is a table describing the same rules. It may seem strange and even
useless, but the XOR function has a very important and useful property: if you
have a number `n`, which is either `1` or `0`, and you use the XOR function
twice with a number `x`, which also is either `1` or `0`, you are returned the
original number `n`.
If we say our `n` is `1`, and `x` is `0`, we see that `(1 XOR 0) XOR 0 = 1`. If
we say `x` is `1`, we get `(1 XOR 1) XOR 1) = 1`.
More generally, we can say that `(n XOR x) XOR x = n`.

You might be wondering how we can use this property to do anything useful.
To answer that, we need to revisit the first cryptogrphy tutorial, where we
discussed ASCII, which is the name of the standard specifying how text is
represented by `1`s and `0`s in computers.
In ASCII, `a` is represented by `01100001`, `b` by `01100010`, and so on and so
forth.
The fact that ASCII text is simply a representation of binary data, we can
input the binary data to the XOR function, enabling us to perform XOR
encryption and decryption.

Because we know that the XOR function can be used twice to get the same result
back, we can use the XOR function both for encryption, and decryption of
information.

> Fun fact: the XOR cipher is a *symmetric* cipher; because it uses the same
> key for both encryption and decryption. There are also
> [*asymmetric*](https://en.wikipedia.org/wiki/Public-key_cryptography)
> ciphers, where there are two keys, one for encryption and one for decryption!

Enough theory, let's have a look at an example. Our message is `TG` and the key
is `1`.

|   |   |   |   |   |   |   |   |   |
|---|---|---|---|---|---|---|---|---|
| T | 0 | 1 | 0 | 1 | 0 | 1 | 0 | 0 |
| 1 | 0 | 0 | 1 | 1 | 0 | 0 | 0 | 1 |
| e | 0 | 1 | 1 | 0 | 0 | 1 | 0 | 1 |

We end up with `0b01100101` which luckily translates to the letter `e`.
The important property of XOR means that we can use the same key to get the `T` back:

|   |   |   |   |   |   |   |   |   |
| - | - | - | - | - | - | - | - | - |
| e | 0 | 1 | 1 | 0 | 0 | 1 | 0 | 1 |
| 1 | 0 | 0 | 1 | 1 | 0 | 0 | 0 | 1 |
| T | 0 | 1 | 0 | 1 | 0 | 1 | 0 | 0 |

Try it out for yourself, either in a text editor or a piece of paper, or using tools on the internet.

> We won't show `G XOR 1` and we leave that as an exercise for you

This example uses a single character as the key, but that is not required, and can in fact be any combination of `1`s and `0`s, and can be of any length.

The longer the key, the harder it is to guess, and therefore the more secure it is. If the key is shorter than the message, we simply repeat the key until the end of the message.

XOR is a simple operation, and you can play around with it on a piece of paper, in a text editor, or you can use online tools like [Cyberchef](https://gchq.github.io/CyberChef/).
With it, you can play around with different encodings and encryption algorithms. Try and change the key, both in length and content, and text to see how the encrypted output changes.

<details><summary>Specifying inputs in Cyberchef</summary>
Cyberchef is a great tool but can be a bit confusing to use.
One thing you have to remember is to specify what kind of
data you have as input. The default is ASCII, so if you have
something else as input, you have to add that as a step in
the recipe. <a href=https://gchq.github.io/CyberChef/#recipe=From_Binary('Space')&input=MDEwMTAxMDAgMDExMDEwMDAgMDExMDAxMDEgMDAxMDAwMDAgMDEwMDAxMTEgMDExMDAwMDEgMDExMTAxMDAgMDExMDEwMDAgMDExMDAxMDEgMDExMTAwMTAgMDExMDEwMDEgMDExMDExMTAgMDExMDAxMTE>Here's</a>
 one example taking binary as input, 
 and <a href=https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true)&input=VkdobElFZGhkR2hsY21sdVp3PT0>here's</a> one with Base64.
</details>

> Tidbit: XOR got its name from the operation it performs, which is called
> "exclusive or". Because XOR represents exclusive or, you might think that we
> also have a (regular) or operation, which would make you right! Wikipedia has
> some really good information about logical operations [here](https://en.wikipedia.org/wiki/Boolean_algebra#Operations).

----------

XOR as an operation is very often used as a part of larger encryption algorithms in cryptography today. A thorough understanding of XOR encryption is very helpful to you if you want to participate in CTFs, study or work with cryptography.

If you have read through this tutorial, we recommend that you try the sixth
and last noob cryptography exam:

- [6. Is This The One? Or Zero?](link.to.task.here)
