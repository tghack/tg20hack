# Writeup - Secret Bases
**Author: Chabz**

**Difficulty: n00b**

**Category: crypto**
___
This task uses a kind of encoding, base64,
meaning we don't need any kind of secret key to
decrypt the given text. All we need is to use the
defined translation rules of base64 encoding to find
the flag. Luckily for us, we don't need to know
these rules ourselves. We can just find a 
base64-decoder, enter the given text, and, 
voilà, we have a flag:
```
TG20{you_can_never_have_enough_secret_bases}
```
