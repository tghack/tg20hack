# Boofy
**Author: Ingeborg**

**Difficulty: easy**

**Category: pwn**

---
This program looks like it's password protected, but we can't seem to find the correct password.

`nc boofy.tghack.no 6003`

or use a mirror closer to you:
* `nc us.boofy.tghack.no 6003` (US)
* `nc asia.boofy.tghack.no 6003` (Japan)

* [download binary](uploads/boofy)
* [download source](uploads/boofy.c)

<details><summary>Hint</summary><p>

It looks like this program has a buffer overflow vulnerability. You can read more [here](https://19.tghack.no/page/Pwntions%20tutorial) or google it!
</p></details>
