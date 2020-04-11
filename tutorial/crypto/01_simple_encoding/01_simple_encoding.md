# Simple encoding

In the real world, encoding is used to represent information that cannot be
properly represented using text, into information that can be represented as
text. 

In a computer, all information is represented using binary; `0`'s and `1`'s,
even images and videos. *Encoding schemes* are what enables us to transfer
images and videos over the internet.

Reading binary is easy for computers, but not so much for us humans.
The [ASCII](https://en.wikipedia.org/wiki/ASCII) encoding scheme helps 
us with this. It defines how readable text is represented by binary. For
instance, the binary `1000001` represents the character `A` and 
`1010100` represents `T`. So now we have a way of translating text
to binary and back again! 

Since binary is a numeral system, we can also write the binary
values in the decimal numeral system, which is the numeral system
we are using in our every day life. This means that we can have a
mapping from letters to numbers by using the ASCII encoding scheme.
As mentioned earlier, the character `A` has the binary value
`1000001`. When expressed in the decimal numeral system, this value
is 65. We can therefore encode the character `A` as the number 65!
For a nice overview over what numbers the different characters are
mapped to, try googling `ascii table`. You can also read more about 
the binary numeral system and how to convert to the decimal numeral 
system [here](https://en.wikipedia.org/wiki/Binary_number).

_Base64_ is another encoding scheme and one of the most commonly 
used today.

> A *scheme* is just a set of rules, and the rules of Base64 dictates how any
> sequence of bits should be written as symbols.
> The rules are not a result of some divine intervention, but simply chosen
> because it seemed like a convenient way to represent the information.

The letters `AB` are represented by the computer in binary as `1000001
1000010`.
When representing this using the Base64 encoding scheme, it is written as
`QUI=`.
But no one goes around remembering that, though! Instead, we use tools to
convert between binary and Base64 representation of data.

The name Base64 stems from it using 64 symbols to represent binary data:
`ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/`.
If something is encoded with Base64, you will only see those symbols.
In addition, you will more often than not see that they end with an equal sign
(`=`), because Base64 encoded strings must have a length divisible by 4, and
equal signs are added to the end to make that happen.

> It is common for ciphers and encoding schemes to require data of a given
> length. When there is not enough data, we need to increase the length. This
> process is known as
> [padding](https://en.wikipedia.org/wiki/Padding_(cryptography))

Try out this interactive illustration of how Base64 encoding works from [Ty Lewis](https://codepen.io/lewistg) on Codepen:
<div>
<p class="codepen" data-height="485" data-theme-id="dark" data-default-tab="result" data-user="lewistg" data-slug-hash="MEQbmB" style="height: 485px; box-sizing: border-box; display: flex; align-items: center; justify-content: center; border: 2px solid; margin: 1em 0; padding: 1em;" data-pen-title="Visualization of Base64 Encoding">

  <span>See the Pen <a href="https://codepen.io/lewistg/pen/MEQbmB">

  Visualization of Base64 Encoding</a> by Ty Lewis (<a href="https://codepen.io/lewistg">@lewistg</a>)

  on <a href="https://codepen.io">CodePen</a>.</span>

</p>

<script async src="https://static.codepen.io/assets/embed/ei.js"></script>
</div>



> It is a lot to say about encoding schemes, binary notation and other
> subjects mentioned here, so feel free to google for stuff you don't understand.

Now that you know what encoding means, you should try the first and second n00b
crypto tasks!  

1. [Number Trouble](link.here)
2. [Secret Bases](link.here)

<details><summary>More on Base64</summary>
Base64 is an encoding scheme using 64 symbols; a-z, A-Z and 0-9. It is often
used to transfer media like images over something designed to transfer text.
This is to ensure that the content being transferred is not modified during
transportation. The way a web browser communicates with a web server, such as
Facebook, is using HTTP, which is designed to transfer text. Meaning that when
you download an image from the internet, it will generally be *encoded* using
Base64 before being sent, and *decoded* upon arriving at your computer, before being
displayed to you without the actual image being modified in any way.

In addition to Base64, we also have an encoding scheme called Base32, which
someone has chosen should use the 32 symbols: A-Z and 2-7.
</details>

<br>
