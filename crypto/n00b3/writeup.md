# Writeup - Shifty Science
**Author: Chabz**

**Difficulty: n00b**

**Category: crypto**
___

We are given a flag, but all the letters are wrong.
It might have been encrypted with a shift cipher. How
can we find the correct shifting value to get the flag?
We know that all flags start with `TG20`. What's the shift
value to go from `BO20` to `TG20`? B -> C is one step,
B -> C -> D is two, and so on. B -> ... -> T is 18 steps, and shifting
all letters in the given text 18 steps, gives us the flag:
```
TG20{please_dont_try_shifts_like_this_at_home}
```
Note that we could also shift backwards, B -> A -> Z -> ... -> T.
This gives us 8 backwards steps, and is also a valid solution.
