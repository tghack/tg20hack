#!/usr/bin/env python3
import random
from rubik import Cube

FLAG = "TG20{RUBIK'S_CUBE_ALGORITHM_IS_REALLY_GOOD_ENCRYPTION}"
FLAG = "TG20{Rubik's_cube_algorithm_is_really_good_encryption}"

def main():
    if len(FLAG) != 54:
        raise Exception("Flag length is {} (must be 54)".format(len(FLAG)))

    cube = Cube(FLAG)
    moves = cube.scramble()
    
    print("I see that you found my server! ")
    print("Before I can let you in, I need to make sure you are human...")
    print("Only humans can solve this, right?\n")
    #print(cube.flat_str())
    print(cube)
    print() 
    print("Oh, and take this! It might help you.")
    print(moves)

if __name__ == '__main__':
    main()
