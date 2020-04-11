# Writeup [The Message](./README.md)

## Task description
**Author: Chabz**

**Difficulty: challenging**

**Category: crypto**

---

One of our radars have detected a weak 
transmission coming from the direction of 
the Earth. I think I know what this is, 
but I'll let you handle it. That's 
fair play, right?

```
--- -... -.- --.- .--. - . -.- ... - -.-. -.- ..- .... .-. --.- -.- ...-
```

<details><summary>Tip</summary>
Remember to include TG20{...} when submitting
the flag!
</details>

---

## Writeup

In this task, we are given the following text:
```
--- -... -.- --.- .--. - . -.- ... - -.-. -.- ..- .... .-. --.- -.- ...-
```

This is quite easily recognizable as morse code.
Translating to text, we get
```
OBKQPTEKSTCKUHRQKV
```

Looks like the text has been encrypted in some
way. There'a actually a hint to the cipher
used in the task description: `That's fair play, right?`
Turns out there's a cipher called [Playfair](https://en.wikipedia.org/wiki/Playfair_cipher),
and lots of tools to break it. Using [this](https://www.quinapalus.com/cgi-bin/playfair)
for instance, we get the following text:
```
helpussheiscomingx
```

The `x` at the end is caused by padding,
so we remove it before we submit the flag:
```
TG20{helpussheiscoming}
```
