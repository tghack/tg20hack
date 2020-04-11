# Vigenere Cipher

In this part of the tutorial we will show you how to break the Vigenere
cipher used in the cryptography exam [Mega Shifting](link.to.task.here). 
We saw that one way of breaking the shift cipher is to use frequency analysis. 

In a shift cipher every 
letter has been changed by moving 1, 2, 3 or more steps in the alphabet.
For example if you have the letter combination "abc" and you shift 1 step,
you get "bcd" instead. A big weakness with the shift cipher is that
we know approximately how many times a letter should appear in the English 
language. The letter "E" is by far the most common letter in English.
You can try to hide a message by changing every E to F. However, then
F would probably appear most frequently in your text, and someone could use that
to figure out that F should have been E. 

The Vigenere cipher tries to solve this problem by trying to make sure that a 
text cannot be broken with frequency analysis. In other words, if E is changed 
to F with a shift cipher, and we know that E should appear most often in a text 
in English, then it will be particularly suspicious when F appears most often 
instead. A hacker will know right away that F is E in disguise! A way to avoid 
this would be to not change EVERY E into F, but maybe only change one E to F, 
and then change another E to G or Z or any letter. Thus, when a hacker tries to 
count the letters they will not see any letter that appears most often! 

The Vigenere cipher has a key. For example “123” could be a key. With the “123” 
key the text “hey” would be changed into: “iga”. "h" has been shifted 1 time, 
"e" has been shifted 2 times and "y" has been shifted 3 times. If the word had 
been longer than “hey” for example “hey hacker”, you would just repeat the “123” 
encryption key several times. So “hey hacker” would become “iga icflgu”. 

Here is another example.
Given the secret word `TG`, the first letter of the text is shifted by 19
positions and the second letter of the text by 6.  Because we have chosen such
a short secret word, the text to encrypt is most likely longer. If this is the
case, we simply repeat the secret word and perform the same shift operations as
described before.

If we want to encrypt the text `ENCRYPTION` with the secret word `TG`, we do this:

|            |    |    |    |    |    |    |    |    |    |    |
|------------|----|----|----|----|----|----|----|----|----|----|
| Plaintext  |  E |  N |  C |  R |  Y |  P |  T |  I |  O |  N |
| Secret     |  T |  G |  T |  G |  T |  G |  T |  G |  T |  G |
| Shifts     | 19 |  6 | 19 |  6 | 19 |  6 | 19 |  6 | 19 |  6 |
| Ciphertext |  X |  T |  V |  X |  R |  V |  M |  O |  H |  T |

Khan Academy has an informative video on the subject of
[polyalphabetic substitution ciphers](https://www.khanacademy.org/computing/computer-science/cryptography/crypt/v/polyalphabetic-cipher)
that I recommend you watch.
In addition, Cornell University also have a good resource regarding
[how to break](http://pi.math.cornell.edu/~mec/2003-2004/cryptography/polyalpha/polyalpha.html)
polyalphabetic substitution ciphers.

With modern computers it is possible to try out all key combinations when you 
know they key length. For example, if you did not know that the key was “123” 
you could try all 3-key length combinations.
For example “245”, “8 14 12”, “22 1 5” and etc. It is possible to write a 
program to do this, but you can also use an existing tool. We recommend Cryptool 
for this. You can download Cryptool here:

https://www.cryptool.org/en/ct1-downloads

You can open Cryptool and paste in the ciphertext.
Then choose “Analysis -> Symmetric Encryption (Classic) -> Ciphertext Only -> Vigenere.
Write “3” inside the key length field that shows up. Cryptool will then try 
out all “3”-combination keys and give you the result that most resembles English text. 
[Cryptool first step](./vigenere_tutorial_1.jpg) and
[Cryptool second step](./vigenere_tutorial_2.jpg) show the first and second 
step in Cryptool. (vigenere_tutorial) One interesting fact about the Vigenere 
cipher is that it is completely unbreakable if the key is equally long as 
the ciphertext!  

You should give the next exam a try:

- [5. Mega Shifting](link.to.task.here)
