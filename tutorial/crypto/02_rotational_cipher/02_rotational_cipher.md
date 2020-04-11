# Shift cipher

Previously, we explained encoding, which has an obvious problem.  It does not
secure your information, because the translation of data is public information.
This means that anyone can decode your information simply by knowing how it was
encoded.  In order to avoid this problem, and to secure your information
properly, you have to use encryption, which means that we must introduce a
secret that must be known in order to decrypt the information.  One of the
earliest and simplest examples of encryption is the **shift cipher**.

Base64 encoding works by mapping binary information to a special alphabet.
Shift cipher on the other hand works by choosing a secret; the shift key. The
shift key is used to construct a secret alphabet, which functions as a mapping
between the plaintext alphabet; a-z and A-Z, and the secret alphabet which is
the same as the plaintext alphabet, but shifted a number of times based off of
the shift key.

![Shift cipher illustration](https://storage.googleapis.com/tghack-public/shift_cipher.svg)

To illustrate this, the above image shows the mapping between the plaintext
alphabet and the secret alphabet when the secret shift key is -3.  The text
`hello world` shifted three times backwards in the alphabet becomes `ebiil
tloia`.  That's all there is to the shift cipher!  This is not a strong form of
encryption, but it is a start.


Let us try to solve the [Shifty Science exam](link.to.task.here) together. In this task we see a
broken flag that has been shifted around by our researcher. Look at the flag:
`BO20{xtmiam_lwvb_bzg_apqnba_tqsm_bpqa_ib_pwum}`, it is almost unrecognizable!
What could have happened to it? We know all TG20 flags look something like
this: `TG20{some_flag_here}`. Therefore, even though the letters look all wrong,
the structure of the flag seems familiar. It still has the number 20, and two
letters before 20. Only in this case they are "BO" instead of "TG". Someone
transformed TG into BO.

How does TG become BO? In the alphabet, how many steps do we need to go to get
from T to B. Let us count together.

1. Start) T
2. 1) U
3. 2) V
4. 3) W
5. 4) X
6. 5) Y
7. 6) Z
8. 7) A (On this step we start from the beginning of the alphabet again)
9. 8) B

There are eight steps in getting from T to B! Let us now look at G and O. With
some luck there will be eight steps in getting from G to O. Let us count
together again.

1. Start) G
2. 1) H
3. 2) I
4. 3) J
5. 4) K
6. 5) L
7. 6) M
8. 7) N
9. 8) O

Yes! Exactly eight steps. We know know that "TG" has been turned into "BO" by
moving eight steps forward in the alphabet. We can move eight steps for all
letters in `BO20{xtmiam_lwvb_bzg_apqnba_tqsm_bpqa_ib_pwum}` and get the flag.
Can you do the rest yourself?

In this case we managed to find out that you have to move eight steps because we
already knew that the flag format starts with "TG". We tried to find out how
"TG" turnes into "BO" and used that knowledge to shift the rest of the flag.
But what if we did not know this? What if we had no idea that the flag should
start with "TG"? After all, in the real world if someone tried to hide a message
like this, we might not know anything about what words they are trying to shift
in the first place.
Read the next tutorial page to find out how to crck such messages.

You are ready for the next cryptography exam:

- [3. Shifty Science](link.to.task.here)
