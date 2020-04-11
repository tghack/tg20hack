import random
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

    def scramble(self):
        """TODO: add x, y, z notations as well?"""
        moves = ["L", "L'", "R", "R'", "U", "U'", "D", "D'", "F", "F'", "B", "B'", "L2", "R2", "U2", "D2", "F2", "B2"]
        #moves = ["L", "L'", "R", "R'", "U", "U'", "D", "D'", "F", "F'", "B", "B'"]
        scrambled_moves = " ".join(random.choice(moves) for _ in range(50))+'\n'
        
        scrambled_moves = scrambled_moves.replace('L L ', 'L2 ').replace('L L\n', 'L2')
        scrambled_moves = scrambled_moves.replace('R R ', 'R2 ').replace('R R\n', 'R2')
        scrambled_moves = scrambled_moves.replace('U U ', 'U2 ').replace('U U\n', 'U2')
        scrambled_moves = scrambled_moves.replace('D D ', 'D2 ').replace('D D\n', 'D2')
        scrambled_moves = scrambled_moves.replace('F F ', 'F2 ').replace('F F\n', 'F2')
        scrambled_moves = scrambled_moves.replace('B B ', 'B2 ').replace('B B\n', 'B2')
        scrambled_moves = scrambled_moves.strip()

        self.do_moves(scrambled_moves)
        return scrambled_moves

    def flat_str(self):
        return ''.join([''.join([str(p) for p in row if p not in string.whitespace]) for row in self.cube])


def rev(moves):
    return ' '.join([i.strip("'") + " '"[len(i):] for i in moves.split()[::-1]])


if __name__ == '__main__':
    msg = "THIS_IS_A_MESSAGE_FOR_TESTING_PURPOSES_ONLY_HAHAHAHAHA"

    cube = Cube(msg)
    print(cube)
    print('-'*12)
    moves = cube.scramble()

    print(cube)
    print(moves)

    print('-'*12)
    moves = rev(moves)
    print(moves)
    cube.do_moves(moves)
    print(cube.flat_str())
