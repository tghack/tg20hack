# Writeup - Poke
**Author: Ingeborg**

**Difficulty: easy**

**Category: misc**

---

We get an image called unowns.png. Viewing the image, we see that they appear
to be symbols of some sort. Googling unown or knowing about them beforehand,
lets us know that they are [these](https://en.wikipedia.org/wiki/Unown). We can
find an alphabet of these online and try to read them. It turns out to say:
"remember to examine the ". This doesn't seem to help us at the moment, so
let's move on.

Examining the file with binwalk, we see that it contains 3 seperate png files.
Let's extract them:
```console
$ binwalk -D='png:png' unowns.png
```
We can now see three seperate png images. The first one, appears similar to the
unowns.png. The second one is an image of some text. This looks a lot like
pikachu-speak. Googling around, we see that there is pikachu-flavoured esolang
based on brainfuck. We can find a useful [decoder](https://www.dcode.fr/pikalang-language)
online. Sadly, decoding the letters on the image doesn't lead us anywhere.

Looking more closely at this file, hereby renamed pika.png, either via strings
or exiftool, we see a long base64-looking string. Via exiftool there are some
added "."-characters. Remove these and decode it:

```console
$ cat thebase64 | tr -d "." | base64 -d > data
```

Checking the data, we see that it is a zip file and it is password protected.  
```console
$ file data
zip

$ unzip data
password_prompt.
```

We can move onto the last png for now. It is a small image of the pokemon
growlithe. Considering that lsb is a common method of hiding data in images,
we can try to check for this. There are several tools for doing this available,
one example of these is [stegolsb](https://github.com/ragibson/Steganography).
(There is also a hint for this tool as an added caeser ciphered string of "pip
install stego-lsb" in the growlithe image)
Extract using stegolsb:
```console
$ stegolsb steglsb -r -i growly.png  -o out.txt
pwd is 58growliness
```

This password can be used to unzip the zip file found embedded as a comment in
the pika.png. We now see a text file containing more pikalang code. This can be
decoded [here](https://www.dcode.fr/pikalang-language), and we get the last part
 of the flag. This is combined with the first flag and surrounded with "TG20{}",
 so that the final flag is TG20{remember to examine the foo bar dog closely}

---
