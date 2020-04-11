# Bufferfly
**Author: Ingeborg**

**Difficulty: challenging**

**Category: pwn**

---

We've been hunting the space goblins for quite some time now. However, we're
still having some trouble identifying their leader. In our last mission, we
found a mysterious-looking chest that we think might contain some useful
information.
Could you help us open it?

```console
nc bufferfly.tghack.no 6002
```

* [download binary](uploads/bufferfly)
* [download source](uploads/bufferfly.c)

<details><summary>Hint</summary><p>
It might be a good idea to read up on [buffer overflows](https://19.tghack.no/page/Pwntions%20tutorial)
</p></details>

<details><summary>Hint</summary><p>
Mprotect is a very useful function that can be used to make areas of memory executable.
</p></details>
