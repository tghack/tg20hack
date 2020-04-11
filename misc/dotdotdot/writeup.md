# Writeup [.-.-.- .-.-.- .-.-.-](README.md)

## Task description
**Author: kristebo**

**Difficulty: Challenging**

**Category: misc**

Solve this

```
.---$'4c 53 41 74 4c 53 34 67 4c 69 34 74 4c 53 30 67 4c 53 30 74 4c 53 30 67 65 79 34 74 4c 53 41 75 49 43 38 67'-------------------------\
| /-$'76 49 43 34 67 4c 69 34 75 49 43 30 74 4c 53 41 76 49 43 34 75 49 43 30 75 49 43 38 67 4c 53 30 74 49 43 34 75 4c 53 41 75 4c 53'--\ |
| |  _________   | || |    ______    | || |              | || |  ____  ____  | || |      __      | || |     ______   | || |  ___  ____   | |
| | |  _   _  |  | || |  .' ___  |   | || |              | || | |_   ||   _| | || |     /  \     | || |   .' ___  |  | || | |_  ||_  _|  | |
| | |_/ | | \_|  | || | / .'   \_|   | || |    ______    | || |   | |__| |   | || |    / /\ \    | || |  / .'   \_|  | || |   | |_/ /    | |
| |     | |      | || | | |    ____  | || |   |______|   | || |   |  __  |   | || |   / ____ \   | || |  | |         | || |   |  __'.    | |
| |    _| |_     | || | \ `.___]  _| | || |              | || |  _| |  | |_  | || | _/ /    \ \_ | || |  \ `.___.'\  | || |  _| |  \ \_  | |
| |   |_____|    | || |  `._____.'   | || |              | || | |____||____| | || ||____|  |____|| || |   `._____.'  | || | |____||____| | |
| |              | || |              | || |              | || |              | || |              | || |              | || |              | |
| | &-'d3 d3 14 94 93 24 96 c4 76 43 35 c4 57 43 34 94 57 43 34 94 57 43 35 c4 57 14 97 c4 76 43'$---------------------------------------/ |
  \-'14 96 c4 76 03 35 c4 76 03 35 c4 47 14 96 c4 57 43 34 94 67 14 96 c4 57 03 34 94 57 14 96 c4 57 03 34 94 57 14 96 c4 76 43 35 c4'$----/
```

## Solution:
This is some really nice ASCII-art, but what are the numbers around the edge?

We can see that the numbers and characters probably are hexadecimal. 
That is because they are numbers between 0-9 and letters ranging from `a` to `f`,
just like hexadecimal numbers. What can these numbers be?

Maybe the numbers are characters (ASCII) written as hexadecimal?
This is probably it, since no numbers are bigger than `7F`.
ASCII is characters represented as a byte. A byte can be written in many different ways, as 8 binary numbers, or as two hexadecimal numbers. [The ASCII table spans from 0 to 7F, where each number is a character.](http://asciiset.com/)


If we copy all the numbers straight from the art, like in the snippet below, ...
```
4c 53 41 74 4c 53 34 67 4c 69 34 74 4c 53 30 67 4c 53 30 74 4c 53 30 67 65 79 34 74 4c 53 41 75 49 43 38 67
76 49 43 34 67 4c 69 34 75 49 43 30 74 4c 53 41 76 49 43 34 75 49 43 30 75 49 43 38 67 4c 53 30 74 49 43 34 75 4c 53 41 75 4c 53
76 49 43 34 67 4c 69 34 75 49 43 30 74 4c 53 41 76 49 43 34 75 49 43 30 75 49 43 38 67 4c 53 30 74 49 43 34 75 4c 53 41 75 4c 53
76 03 35 c4 47 14 96 c4 57 43 34 94 67 14 96 c4 57 03 34 94 57 14 96 c4 57 03 34 94 57 14 96 c4 76 43 35 c4 14 96 c4 76 03 35 c4
```

... and convert them from hexadecimal to characters, it simply returns gibberish. 
There is no flag in the result of the conversion, which we see below:
```
LSAtLS4gLi4tLS0gLS0tLS0gey4tLSAuIC8杶IC4gLi4uIC0tLSAvIC4uIC0uIC8gLS0tIC4uLSAuL卶IC4gLi4uIC0tLSAvIC4uIC0uIC8gLS0tIC4uLSAuL卶35ÄGÄWC4gÄW34WÄW34WÄvC5ÄÄv35Ä
```

There's probably more to this story than just copy pasta straight from the art. 
Lets try something completely different:

Could this be the-most-popular-weekend-programming-language: 
[AsciiDots](https://www.vice.com/en_us/article/ezmj5z/the-most-popular-weekend-programming-languages)? 
We can see `.---$'4c 53` and so on in the first line of the ASCII-art. 
If we follow the `-`,`|`,`\` and `/`, we end up at `&-'d3 `.
[Just like the esoteric language AsciiDots](https://github.com/aaronjanse/asciidots).

If we run the ASCII-art as AsciiDots [here](https://asciidots.herokuapp.com/index.html), we get this output:
```
4c 53 41 74 4c 53 34 67 4c 69 34 74 4c 53 30 67 4c 53 30 74 4c 53 30 67 65 79 34 74 4c 53 41 75 49 43 38 67 4c 53 34 67
4c 69 41 75 49 43 30 75 4c 69 41 75 49 43 30 75 4c 69 41 76 49 43 34 75 4c 69 41 74 4c 53 30 67 4c 53 30 67 4c 69 41 76 
49 43 34 67 4c 69 34 75 49 43 30 74 4c 53 41 76 49 43 34 75 49 43 30 75 49 43 38 67 4c 53 30 74 49 43 34 75 4c 53 41 75 
4c 53 34 67 4c 79 41 75 4c 53 34 75 49 43 34 75 49 43 34 75 4c 53 34 67 4c 69 42 39 49 41 3d 3d
```

It seems like the AsciiDots web page may be a little unstable at times. The output should
be in four rows, and there should only be pairs of hex numbers. If there are some groups
of 3 or singles, then you should run it again.

It's even better to use [try it online-Asciidots.](https://tio.run/#asciidots) 

The hex values above might be the hex representation of ASCII. Now, if we 
convert it to the character (called the Unicode representation on 
[Wikipedia](https://en.wikipedia.org/wiki/ASCII)), we get the following piece of text.
You may also check this [ASCII table](http://www.asciitable.com/):
```
LSAtLS4gLi4tLS0gLS0tLS0gey4tLSAuIC8gLS4gLiAuIC0uLiAuIC0uLiAvIC4uLiAtLS0gLS0gLiAvIC4gLi4uIC0tLSAvIC4uIC0uIC8gLS0tIC4uLSAuLS4gLyAuLS4uIC4uIC4uLS4gLiB9IA==
```
Because of the padding `==` at the end this looks like a Base64 encoded string.
Lets try to decode it:
```bash
$ echo "LSAtLS4gLi4tLS0gLS0tLS0gey4tLSAuIC8gLS4gLiAuIC0uLiAuIC0uLiAvIC4uLiAtLS0gLS0gLiAvIC4gLi4uIC0tLSAvIC4uIC0uIC8gLS0tIC4uLSAuLS4gLyAuLS4uIC4uIC4uLS4gLiB9IA==" |base64 --decode
- --. ..--- ----- {.-- . / -. . . -.. . -.. / ... --- -- . / . ... --- / .. -. / --- ..- .-. / .-.. .. ..-. . } %
```

```
- --. ..--- ----- {.-- . / -. . . -.. . -.. / ... --- -- . / . ... --- / .. -. / --- ..- .-. / .-.. .. ..-. . }
```
 Can this be the flag? Where's the `TG20` part?
 It looks like [morse code](https://en.wikipedia.org/wiki/Morse_code#/media/File:International_Morse_Code.svg) written as dashes and dots with `/` as space:

* `-` is `T`
* `--.` is `G`
* `..---` is `2`
* `-----` is `0`

Because `{` and `}` doesn't have a symbol in morse, we must translate the rest and rebuild the flag in the right format, `TG20{...}`, before we deliver. 


```
TG20{WE NEEDED SOME ESO IN OUR LIFE}
```

funfact:
```
.-.-.- .-.-.- .-.-.-
```
is
```
...
```
aka `STOP STOP STOP` in  morse .
