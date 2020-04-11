import argparse
import os
import random
import sys


def parse_puzzles(filename, d):
    with open(filename, 'r') as f:
        Lines = f.readlines()
    
    puzzle_cnt = 0
    pzl = []
    for line in Lines:
        if "Solution" in line:
            d["puzzle{}".format(puzzle_cnt)] = pzl
            pzl = []
            continue
    
        if "---END---" in line:
            d["sol{}".format(puzzle_cnt)] = pzl
            pzl = []
            puzzle_cnt += 1
            continue
            
        pzl.append(line)

    d["count"] = puzzle_cnt


def read_input(limit):
    cnt = 0
    solution = ""
    while True:
        cnt += 1

        if cnt == limit:
            print("Maximum numbers of instructions exceeded!")
            sys.exit()

        tmp = input("").lstrip() + "\n"
        if "EOF" in tmp:
            break

        solution += tmp

    return solution


def level1(filename):
    print("Starting level 1....")

    # Step 1: Get puzzles
    puzzles = {}
    parse_puzzles(filename, puzzles)

    # Step 2: Randomize puzzle ids to send random puzzle
    rand = random.sample(range(puzzles["count"]), puzzles["count"])

    for i in rand:
        print("".join(puzzles["puzzle{}".format(i)]))
        print("Only send me the grid. It needs the same borders.")
        print("End with new line containing 'EOF'")

        solution = "".join(puzzles["sol{}".format(i)])
        in_solution = read_input(100)
        if in_solution != solution:
            print(in_solution)

            print("Try again...! :'(")
            sys.exit()
            
        print("Yatta~~ Kawaii nonogram*\(^_^ )/*")

    print("NANI?! You Nonogram master!\n")


def print_lvl2_example():
    print("EXAMPLE:")
    print("8")
    print("0=#ffffff")
    print("1=#000000")
    print("2=#d60000")
    print("3=#ff9900")
    print("4=#ffec3b")
    print("5=#4cb050")
    print("6=#2197f4")
    print("7=#9d27b1")
    print("9 9")
    print("")
    print("Puzzle:")
    print("--------------------------------------------")
    print("                         |               1(1) 1(1) 1(1)               |")
    print("                         |          1(1) 1(2) 1(3) 1(2) 1(1)          |")
    print("                         |     1(1) 1(2) 1(3) 1(4) 1(3) 1(2) 1(1)     |")
    print("                         |     1(2) 1(3) 1(4) 1(5) 1(4) 1(3) 1(2)     |")
    print("                         |     1(3) 1(4) 1(5) 1(6) 1(5) 1(4) 1(3)     |")
    print("                         |     1(4) 1(5) 1(6) 1(7) 1(6) 1(5) 1(4)     |")
    print("                         |3(1) 1(1) 1(1) 1(1) 1(1) 1(1) 1(1) 1(1) 3(1)|")
    print("--------------------------------------------")
    print("                3(1) 3(1)|                 |")
    print(" 1(1) 3(2) 1(1) 3(2) 1(1)|                 |")
    print("           1(1) 7(3) 1(1)|                 |")
    print("           1(1) 7(4) 1(1)|                 |")
    print("           1(1) 5(5) 1(1)|                 |")
    print("           1(1) 3(6) 1(1)|                 |")
    print("           1(1) 1(7) 1(1)|                 |")
    print("                     1(1)|                 |")
    print("                         |                 |")
    print("--------------------------------------------")
    print("\nOnly send me the grid. It needs the same borders.")
    print("End with new line containing 'EOF'")
    print("")
    print("SOLUTION TO EXAMPLE:")
    print("-------------------")
    print("|  1 1 1   1 1 1  |")
    print("|1 2 2 2 1 2 2 2 1|")
    print("|1 3 3 3 3 3 3 3 1|")
    print("|1 4 4 4 4 4 4 4 1|")
    print("|  1 5 5 5 5 5 1  |")
    print("|    1 6 6 6 1    |")
    print("|      1 7 1      |")
    print("|        1        |")
    print("|                 |")
    print("-------------------")
    print("EOF")


def level2(filename):
    print("Starting level 2....")
    print_lvl2_example()

    # Step 1: Get puzzles     
    puzzles = {}              
    parse_puzzles(filename, puzzles)
                              
    # Step 2: Randomize puzzle ids to send random puzzle
    rand = random.sample(range(puzzles["count"]), puzzles["count"])
                              
    for i in rand:            
        print("".join(puzzles["puzzle{}".format(i)]))
        print("Only send me the grid. It needs the same borders.")
        print("End with new line containing 'EOF'")

        solution = "".join(puzzles["sol{}".format(i)])
        in_solution = read_input(1000000)
        if in_solution != solution:
            print(in_solution)

            print("Try again...! :'(")
            sys.exit()

        print("Yatta~~ Kawaii nonogram*\(^_^ )/*\n")


def print_flag_puzzle():
    filename = "puzzle-flag.txt"

    # Step 1: Get puzzles
    puzzles = {}
    parse_puzzles(filename, puzzles)

    print("".join(puzzles["puzzle0"]))
    print("Only send me the grid. It needs the same borders.")
    print("End with new line containing 'EOF'")

    solution = "".join(puzzles["sol0"])
    in_solution = read_input(1000000)
    if in_solution != solution:
        print(in_solution)

        print("Try again...! :'(")
        sys.exit()

    print("Yatta~~ Kawaii nonogram*\(^_^ )/*\n")
    print("Even colored? What are you? A nonogram wizard?")

    print("Level 2 finished! Ready for Level 3? 3D puzzles!!!")
    print("READY? Y/n:")
    in_ready = read_input(10)

    print("lol jk <3")
    print("Did you checkout the latest picture? :)")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='Run Space Puzzle challenge with given puzzles')
    parser.add_argument('filename', metavar='F', type=str, nargs='?',
        default=["./puzzles-bw.txt", "./puzzles-color.txt"],
        help='filename of file to fetch puzzles from')

    args = parser.parse_args()

    level1(args.filename[0])
    level2(args.filename[1])
    print_flag_puzzle()

