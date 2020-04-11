# Writeup - Number Trouble
**Author: Chabz**

**Difficulty: n00b**

**Category: crypto**
___
This task gives us a list of numbers that somehow hides a flag.
As we know the flag is made out of letters, we may assume we
have to find a way to convert the numbers to letters. One of
the most common ways to do this is called [ASCII](https://en.wikipedia.org/wiki/ASCII).
By looking at the ASCII encoding table (`man ascii` in the terminal
or find it online), we can map the numbers to their corresponding
character.

The first number is 84. If we look up the decimal value 84 
in the ASCII table, we get the letter T. The second number 
is 71, and this gives us G. We know that all flags start 
with `TG`, so we can safely assume ASCII encoding is the
correct answer to this task. Do the same for the rest of the
numbers given in the task and the flag appears: 
`TG20{numbers_and_text_goes_hand_in_hand}`.
