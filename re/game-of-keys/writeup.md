# Writeup [Game of Keys](README.md)

## Challenge description
**Author: kristebo**

**Difficulty: Easy**

**Category: re**

Download [this file](uploads/keygame.pyc) and get the flag.
You will also need [this wordlist](uploads/wordlist.txt)

---

## Writeup
We have a compiled Python file. If we do normal reverse engineering tricks on it we get some information:
Keygame.pyc is a binaryfile so we cant directly find the source code.
To run it we use Python from CLI like this:

```sh
 python keygame.pyc
input a number: 2
input a number: 2
input a number: 2 
input a number: 2
aa0eaa0e
A^^
     ATA
=L ^ aa0eaa0e = TG37\{ukis!alaf#shnrld!ae ni tdk mnhn\|
```
Strange, you are asked for a number four times, and we get some strange output.

To know more we must investigate the file closer. We run the command:
`file keygame.pyc`

The command gives us information about the Python version and that the file 
has been compiled into byte-code.

If we run strings keygame.pyc we get the following:

```sh
$ strings keygame.pyc 
cyclec
myGame
matrix
range
append)
selfZ
xdimZ
ydim
keygame.py
__init__
myGame.__init__c
}       x |
wordlist.txtr
openr
stripr
print)
args
kwargsZ
words
liner
keyArray
        make_keys
myGame.make_keysc
NSYDUj0aRQ4IEhEEDQBWRhIJXhcNBREEBEFeDEEVVA5BDF4NDz1M
asciir
ord)
        <genexpr>3
z#myGame.checkdata.<locals>.<genexpr>z
%s ^ %s = %s)
base64Z b64decode
decode
join
zipr
datar$
        checkdata/
myGame.checkdataN)
__name__
__module__
__qualname__r
__main__
input a number: )
        itertoolsr
mgame
inputr
intr*
<module>
```
The file contains much information, but little help here. We can 
use a decompiler for pyc files. Let us try one:

**uncompyle**

```sh
$ uncompyle6 keygame.pyc
# uncompyle6 version 3.4.0
# Python bytecode 3.7 (3394)
# Decompiled from: Python 2.7.13 (default, Sep 26 2018, 18:42:22) 
# [GCC 6.3.0 20170516]
# Embedded file name: ./keygame.py
# Size of source mod 2**32: 1738 bytes
```

We get the source code:

```python
import base64
from itertools import cycle

class myGame:

    def __init__(self, xdim=4, ydim=4):
        self.x = xdim
        self.y = ydim
        self.matrix = []
        for i in range(self.x):
            row = []
            for j in range(self.y):
                row.append(0)

            self.matrix.append(row)

    def make_keys(self, *args, **kwargs):
        words = []
        with open('wordlist.txt') as (f):
            for line in f:
                words.append(line.strip())

            for i in range(self.x):
                for j in range(self.y):
                    self.matrix[j][i] = words[(i + j)]

        keyArray = []
        keyArray.append(self.matrix[args[0]][args[1]])
        keyArray.append(self.matrix[args[2]][args[3]])
        key = ''
        for k in keyArray:
            key = key.strip() + str(k).strip()

        print(key)
        return key

    def checkdata(self, key):
        f = base64.b64decode('NSYDUj0aRQ4IEhEEDQBWRhIJXhcNBREEBEFeDEEVVA5BDF4NDz1M')
        data = f.decode('ascii')
        c = ''.join((chr(ord(c) ^ ord(k)) for c, k in zip(data, cycle(key))))
        print('%s ^ %s = %s' % (data, key, c))


if __name__ == '__main__':
    mgame = myGame(25, 25)
    x = input('input a number: ')
    y = input('input a number: ')
    x1 = input('input a number: ')
    y1 = input('input a number: ')
    data = mgame.make_keys(int(x), int(y), int(x1), int(y1))
    mgame.checkdata(data)
```

Here we have three methods in the class myGame:
The constructor `__init__` 
The second one is called `make_keys`, this takes an infinite amounts of arguments and the third is called `checkdata` takes one.
The first thing that happens is myGame is created as mgame with two arguments: `xdim` and `ydim`. 
These are the dimensions of a two-dimensional array filled with 0.

```python
    def __init__(self, xdim=4, ydim=4):
        self.x = xdim
        self.y = ydim
        self.matrix = []
        for i in range(self.x):
            row = []
            for j in range(self.y):
                row.append(0)

            self.matrix.append(row)
```

Then the program asks for four inputs and saves them to variables `x`,`y`,`x1` and `y1`.
These four are placed into the `make_keys`-method. The first x*y words from wordlist is put into the matrix made in the constructor.
And `x`,`y`,`x1` and `y1`is used as coordinates to make a combined word called key.

```python
    def make_keys(self, *args, **kwargs):
        words = []
        with open('wordlist.txt') as (f):
            for line in f:
                words.append(line.strip())

            for i in range(self.x):
                for j in range(self.y):
                    self.matrix[j][i] = words[(i + j)]

        keyArray = []
        keyArray.append(self.matrix[args[0]][args[1]])
        keyArray.append(self.matrix[args[2]][args[3]])
        key = ''
        for k in keyArray:
            key = key.strip() + str(k).strip()

        print(key)
        return key
```


The last method called is `checkdata`:
```python
   def checkdata(self, key):
        f = base64.b64decode('NSYDUj0aRQ4IEhEEDQBWRhIJXhcNBREEBEFeDEEVVA5BDF4NDz1M')
        data = f.decode('ascii')
        c = ''.join((chr(ord(c) ^ ord(k)) for c, k in zip(data, cycle(key))))
        print('%s ^ %s = %s' % (data, key, c))
```

Here we can see a xor for each of the characters in `data` and `key`. The key is from the matrix and the data is an ascii-encoded base64 string.
We need to find the right combination of words from the matrix.

So we modify the script and get the flag:

```python
import base64
from itertools import cycle, product, combinations
import random



class myGame():

    def __init__(self, xdim=4, ydim=4):
        self.x=xdim
        self.y=ydim
        self.matrix = []
        for i in range(self.x):
            row = []
            for j in range(self.y):
                row.append(0)
            self.matrix.append(row)
        
        words=[]
        with open('wordlist.txt') as f:
            for line in f:
                words.append(line.strip())
            for i in range(self.x):
                
                for j in range(self.y):
                     self.matrix[j][i]=words[i+j]


    def make_keys(self, *args, **kwargs):



      
        # pick a key:
        keyArray=[]
        
        keyArray.append(self.matrix[args[0]][args[1]])
        keyArray.append(self.matrix[args[2]][args[3]])

        
        key=''
        for k in keyArray:
            key=key.strip()+str(k).strip()

        return key


    def checkdata(self, key):
        f=base64.b64decode(b'NSYDUhoVWQ8SQVcOAAYRFQkORA4FQVMDQQ5fQhUEWUYMDl4MHA==')
        data=f.decode('ascii')

        c = ''.join(chr(ord(c)^ord(k)) for c,k in zip(data, cycle(key)))
        if c.__contains__('TG20{this'):
            print('%s ^ %s = %s' % (data, key, c))
        


if __name__ == "__main__":
    mgame=myGame(25, 25)
  
    keys=[]
    for i in range(30000):
        keys.append(mgame.make_keys(random.randint(0,24), random.randint(0,24), random.randint(0,24), random.randint(0,24)))
        
    print(len(keys))

    for key in keys:
        mgame.checkdata(key)
```
TG20{this flag should be on teh moon}
