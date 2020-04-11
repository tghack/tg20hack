# Writeup [Cubik's Rube](README.md)

## Task description
**Author: zup**

**Difficulty: easy**

**Category: misc**

Connect to the server:

```shell
nc cubiks.tghack.no 7001
```

or use a mirror closer to you:
* `nc us.cubiks.tghack.no 7001` (US)
* `nc asia.cubiks.tghack.no 7001` (Japan)

---

## Solution:
When connecting to the server we see this:

```
I see that you found my server! 
Before I can let you in, I need to make sure you are human...
Only humans can solve this, right?

    _ri
    b{R
    d_a
2c} _mn oeu b_a
0re oh_ sil Gr'
oil yls unk gtg
    cp_
    ote
    yiT

Oh... and take this! It might help you.
U2 B D L' R' F2 L R L2 R D U' D' R2 B' B' D' F2 D2 L U R2 R2 L2 F D2 F' B2 B2 R2 B2 U L B F2 L U F' B D' U2 F' D' L F2 L R' B' R
```

It looks like a strange cross. We can also see that there are some strange combination of letters at the end.
If we search for these strange letters on Google, we quickly find out that this is the [standard notation for
rotations of the Rubik\'s Cube](https://ruwix.com/the-rubiks-cube/notation/). Each letter refers to which
side of the cube that should be rotated. *F* means *front*, and if the letter is not marked by a *\'* it means
that you should rotate the front side clockwise. If it *is* marked it should be rotated counterclockwise.

The cross looks like a Rubik\'s Cube. It has a top side (*U*), a left side (*L*), a right side (*R*), a backside (*B*),
and a bottom side (*D*):

```
  U
L F R B
  D
```

We must unscramble the cube to get the flag. But how do we do this?
The Rubik\'s Cube notation that we acquired is probably the moves that was done by the server
to scramble the cube. If we do the exact opposite moves, we should be able to unscramble it
and read the flag!

To reverse all of the moves we can first reverse the order of the letters (note that the single quotes and numbers should stick to its original letter), add a single quote to the letters that don\'t have any, 
and then remove the quote for those letters that have one. The result will show us the moves that solves the cube.

```python
def rev(moves):
    result = []
    for i in moves.split()[::-1]:
        result.append(i.strip("'") + " '"[len(i):])
    return ' '.join(result)
```
```python
>>> rev("U2 B D L' R' F2 L R L2 R D U' D' R2 B' B' D' F2 D2 L U R2 R2 L2 F D2 F' B2 B2 R2 B2 U L B F2 L U F' B D' U2 F' D' L F2 L R' B' R")

"R' B R L' F2 L' D F U2 D B' F U' L' F2 B' L' U' B2 R2 B2 B2 F D2 F' L2 R2 R2 U' L' D2 F2 D B B R2 D U D' R' L2 R' L' F2 R L D' B' U2"
```

Now that we know how to solve the cube, we must do some programming. There are lots of different 
Rubik\'s Cube projects all over the internet if we want to save some time!

I found a short Rubik's Cube [implementation](https://codegolf.stackexchange.com/a/92608) using *numpy* that I 
customized a bit.

```python
import string
import numpy as np

class Cube:
    def __init__(self, cube_str=False):
        self.last = None #store last move to repeat for inverse or double
        self.cube = None

        if cube_str:
            colors = list(cube_str)
        else:
            colors = list("YYYYYYYYYRRRGGGOOOBBBRRRGGGOOOBBBRRRGGGOOOBBBWWWWWWWWW")
        
        assert len(colors) == 54

        self.cube = [
        [' ',' ',' ','{0}','{1}','{2}',' ',' ',' ',' ',' ',' '],
        [' ',' ',' ','{3}','{4}','{5}',' ',' ',' ',' ',' ',' '],
        [' ',' ',' ','{6}','{7}','{8}',' ',' ',' ',' ',' ',' '],
        ['{9}','{10}','{11}','{12}','{13}','{14}','{15}','{16}','{17}','{18}','{19}','{20}'],
        ['{21}','{22}','{23}','{24}','{25}','{26}','{27}','{28}','{29}','{30}','{31}','{32}'],
        ['{33}','{34}','{35}','{36}','{37}','{38}','{39}','{40}','{41}','{42}','{43}','{44}'],
        [' ',' ',' ','{45}','{46}','{47}',' ',' ',' ',' ',' ',' '],
        [' ',' ',' ','{48}','{49}','{50}',' ',' ',' ',' ',' ',' '],
        [' ',' ',' ','{51}','{52}','{53}',' ',' ',' ',' ',' ',' ']
        ]

        self.cube = np.array([[piece.format(*colors) for piece in row] for row in self.cube])
        
    def __str__(self):
        """Insert a few blank columns for pretty printing"""
        tmp = np.copy(self.cube)
        tmp = np.insert(tmp, 3, values=' ', axis=1)
        tmp = np.insert(tmp, 7, values=' ', axis=1)
        tmp = np.insert(tmp, 11, values=' ', axis=1)
        return '\n'.join([''.join([str(piece) for piece in row]) for row in tmp])
    
    def i(self): #triple move (inverse)
        self.last()
        self.last()
    
    def d(self): #double move
        self.last()
    
    def U(self): #clockwise upface (yellow)
        self.cube[:3,3:6] = np.rot90(self.cube[:3,3:6],3)
        self.cube[3] = np.roll(self.cube[3],9)
        self.last = self.U
    
    def D(self): #clockwise downface (white)
        self.cube[6:,3:6] = np.rot90(self.cube[6:,3:6],3)
        self.cube[5] = np.roll(self.cube[5],3)
        self.last = self.D
    
    def F(self): #clockwise frontface (green)
        self.cube[2:7,2:7] = np.rot90(self.cube[2:7,2:7],3)
        self.last = self.F
    
    def B(self): #clockwise backface (blue)
        self.cube[3:6,9:] = np.rot90(self.cube[3:6,9:],3)
        tempCube = np.copy(self.cube)
        self.cube[:,:9],self.cube[1:-1,1:8] = np.rot90(tempCube[:,:9]),tempCube[1:-1,1:8]
        self.last = self.B
    
    def R(self): #clockwise rightface (orange)
        self.cube[3:6,6:9] = np.rot90(self.cube[3:6,6:9],3)
        tempCube = np.copy(self.cube)
        self.cube[:6,5],self.cube[3:6,9],self.cube[6:,5] = tempCube[3:,5],tempCube[2::-1,5],tempCube[5:2:-1,9]
        self.last = self.R
    
    def L(self): #clockwise leftface (red)
        self.cube[3:6,:3] = np.rot90(self.cube[3:6,:3],3)
        tempCube = np.copy(self.cube)
        self.cube[3:,3],self.cube[3:6,-1],self.cube[:3,3] = tempCube[:6,3],tempCube[:5:-1,3],tempCube[5:2:-1,-1]
        self.last = self.L

    def do_moves(self, move_str):
        move_str = move_str.replace("'",'i').replace('2','d').replace(' ','')
        moves = [getattr(self, name) for name in move_str]
        for move in moves:
            move()

    def flat_str(self):
        return ''.join([''.join([str(p) for p in row if p not in string.whitespace]) for row in self.cube])
```



We can now create a new cube that looks just like the scrambled cube sent by the server. Next, we can solve 
the cube using the `do_moves` method! We already have the sequence of moves to solve it, so let\'s try that:

```python
#!/usr/bin/env python3
from rubik import Cube

def rev(moves):
    result = []
    for i in moves.split()[::-1]:
        result.append(i.strip("'") + " '"[len(i):])
    return ' '.join(result)

scrambled = """
    _ri        
    b{R        
    d_a        
2c} _mn oeu b_a
0re oh_ sil Gr'
oil yls unk gtg
    cp_        
    ote        
    yiT        
"""
moves = "U2 B D L' R' F2 L R L2 R D U' D' R2 B' B' D' F2 D2 L U R2 R2 L2 F D2 F' B2 B2 R2 B2 U L B F2 L U F' B D' U2 F' D' L F2 L R' B' R"

print(scrambled)

scrambled = scrambled.replace("\n", "").replace(' ', '')
print("Scrambled flag:", scrambled)
print()

rev_moves = rev(moves)
print("Reversed moves:", rev_moves)

cube = Cube(scrambled)
cube.do_moves(rev_moves)
print("Reversed cube:")
print(cube)
print()

flag = cube.flat_str()
print("Flag:", flag)
```

```
$ python3 solve.py 

    _ri        
    b{R        
    d_a        
2c} _mn oeu b_a
0re oh_ sil Gr'
oil yls unk gtg
    cp_        
    ote        
    yiT        

Scrambled flag: _rib{Rd_a2c}_mnoeub_a0reoh_silGr'oilylsunkgtgcp_oteyiT

Reversed moves: R' B R L' F2 L' D F U2 D B' F U' L' F2 B' L' U' B2 R2 B2 B2 F D2 F' L2 R2 R2 U' L' D2 F2 D B B R2 D U D' R' L2 R' L' F2 R L D' B' U2
Reversed cube:
    TG2        
    0{R        
    ubi        
k's _cu be_ alg
ori thm _is _re
all y_g ood _en
    cry        
    pti        
    on}        

Flag: TG20{Rubik's_cube_algorithm_is_really_good_encryption}
```

Nice, we proved that we are human and got the flag! Rubik\'s Cubes are great puzzles when you are bored :)


```
TG20{Rubik's_cube_algorithm_is_really_good_encryption}
```

