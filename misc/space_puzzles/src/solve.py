import numpy as np
from pwn import *
import os

#io = remote("localhost", 7002)
io = remote("puzzle.tghack.no", 7002)


#############################################
###### PARSE PZL FROM izarion/Nonogram ######
#############################################
def parse_pzl(filename, dictionary):
    print("[3] Parsing .pzl file...")
    with open(filename, 'r') as f:
        Lines = f.readlines()

    idx = 0
    num_colors = int(Lines[0])
    colors = Lines[1:num_colors + 1]

    idx = num_colors + 2 # lines of color plus empty line
    grid = Lines[num_colors + 2].split(" ")

    idx += 2 # grid line plus empty line
    vertical_len = int(grid[0])
    vertical = Lines[idx: idx + vertical_len]

    idx += vertical_len + 1 # horizontal numbers and empty line
    horizontal_len = int(grid[1])
    horizontal = Lines[idx: idx + horizontal_len]

    cnt = 0
    color_dict = {}
    for color in colors:
        color = color.strip()
        color_dict[color] = cnt
        cnt += 1

    dictionary["color_ids"] = color_dict
    dictionary["num_colors"] = num_colors
    dictionary["colors"] = colors
    dictionary["grid"] = " ".join(grid)
    dictionary["h_len"] = horizontal_len
    dictionary["v_len"] = vertical_len
    dictionary["horizontal"] = horizontal
    dictionary["vertical"] = vertical


################################################
###### DRAW BLACK/WHITE NONOGRAM SOLUTION ######
################################################
def draw_bw_solution(dictionary):
    print("[4] Drawing black/white solution..")

    solution = []

    black = "X"
    white = " "

    idx = 0

    solution.append("-" * (1 + (dictionary["h_len"]) * 2) + "\n")
    for line in dictionary["vertical"]:
        line = line.split()
        elems = int(line[0])

        solution.append("|")
        for i in range(elems):
            idx = 1 + (i * 4)
            seq = line[idx:idx + 4]

            if seq[1:] == ['255', '255', '255']:
                num = int(seq[0])

                if i == (elems - 1):
                    solution.append("{} ".format(white) * (num - 1))
                    solution.append("{}|".format(white))
                else:
                    solution.append("{} ".format(white) * num)

            if seq[1:] == ['0', '0', '0']:
                num = int(seq[0])

                if i == (elems - 1):
                    solution.append("{} ".format(black) * (num - 1 ))
                    solution.append("{}|".format(black))
                else:
                    solution.append("{} ".format(black) * num)

        solution.append("\n")

    solution.append("-" * (1 + (dictionary["h_len"]) * 2) + "\n")
    solution.append("EOF")

    return ''.join(solution)


##########################################
###### DRAW COLOR NONOGRAM SOLUTION ######
##########################################
def draw_color_solution(d):
    print("[4] Drawing colored solution..")

    solution = []

    color_dict = d["color_ids"]
    #print("Color ids: {}".format(color_dict))

    white = " "
    idx = 0

    solution.append("-" * (1 + (d["h_len"]) * 2) + "\n")
    for line in d["vertical"]:
        line = line.split()
        elems = int(line[0])

        solution.append("|")
        for i in range(elems):
            idx = 1 + (i * 4)
            seq = line[idx:idx + 4]

            if seq[1:] == ['255', '255', '255']:
                num = int(seq[0])

                if i == (elems - 1):
                    solution.append("{} ".format(white) * (num - 1))
                    solution.append("{}|".format(white))
                else:
                    solution.append("{} ".format(white) * num)

                continue

            num = int(seq[0])
            hexcolor = "#{:02x}{:02x}{:02x}".format(int(seq[1]), int(seq[2]), int(seq[3]))
            c_id = color_dict[hexcolor]
            #print("Color to id {} : {} : {}".format(seq[1:], hexcolor, c_id))

            if i == (elems - 1):
                solution.append("{} ".format(c_id) * (num - 1 ))
                solution.append("{}|".format(c_id))
            else:
                solution.append("{} ".format(c_id) * num)

        solution.append("\n")

    solution.append("-" * (1 + (d["h_len"]) * 2) + "\n")
    solution.append("EOF")

    return ''.join(solution)


def write_to_file(pzl):
    print("[2] Writing ported .pzl to file...")
    #print(pzl)
    with open("tmp.pzl", "w") as f:
        f.write(''.join(pzl))


#############################
###### SOLVING LEVEL 1 ######
#############################
def read_vertical_lvl1(vert_pzl, puzzle):
    print("[0] Reading vertical numbers...")

    lines = []
    cnt = 0
    start_cnt = 0

    second_line = puzzle[0]
    for char in second_line:
        if char is "|":
            break
        start_cnt += 1

    for line in puzzle:
        cnt += 1
        if "--------" in line:
            break

        line = line[start_cnt:]
        line = line.replace("|", "")
        line = line.replace("  ", " 0 ")
        lines.append(line.split())

    #m = np.array(lines)
    #rotated = np.rot90(m, 2)
        
    rotated = np.array(lines).transpose()
    #rotated = np.flip(rotated, 1)
    #print("rotated:\n{}".format(rotated))

    for i in range(len(rotated)):
        if all(v == "|" for v in rotated[i]):
            rotated = rotated[i:]
            break

    for line in rotated:
        elems = []
        #print("line: {}".format(line))
        if all(v == "0" for v in line):
            vert_pzl.append("0\n")
        else: 
            num_elems = 0
            for char in line:
                if char != '0':
                    #print("charrrrr: {}".format(char))
                    char = char.strip('|')
                    num_elems += 1
                    elems.append("{} ".format(char))
            vert_pzl.append("{} {}\n".format(num_elems, ''.join(elems).rstrip())) #.encode("utf-8")))

    return cnt


def read_horizontal_lvl1(pzl, puzzle):
    print("[1] Reading horisontal numbers...")

    for line in puzzle:
        if "--------" in line:
            break
        
        num_elems = 0
        elems = []
        line = line.split()
        #print("line: {}".format(line))
        for char in line:
            #print("charrrrr: {}".format(char))
            if char is '|':
                break

            if char is not ' ':
                num_elems += 1
                char = char.strip('|')
                elems.append("{} ".format(char))


        pzl.append("{} {}\n".format(num_elems, ''.join(elems).rstrip())) #.encode("utf-8"))


'''
I use https://github.com/Izaron/Nonograms to solve the puzzle, 
so I need to port the numbers into the format that solver expects.
The author called the postfix ".pzl". 
'''
def solve_puzzle_level1(grid, puzzle):
    # Port to .pzl
    pzl = []
    pzl.append("{}\n".format(grid))
    pzl.append("\n")

    cnt = 1 
    vertical_pzl = []
    lines = read_vertical_lvl1(vertical_pzl, puzzle[cnt:])
    cnt += lines
    read_horizontal_lvl1(pzl, puzzle[cnt:])
    pzl.append("\n")
    pzl.append(''.join(vertical_pzl))
    pzl.append("\n")
    #print("pzl: {}".format(pzl))

    write_to_file(pzl)
    #print("Puzzle ({}):\n{}".format(grid, pzl))

    # Solve nonogram with solver
    os.system("./Nonograms/build/nonograms_solver -b -i tmp.pzl -o tmp") 
    time.sleep(1)

    # use solver to generate .pzl of image
    os.system("./Nonograms/build/nonograms_solver -b -p tmp0000.png")
    time.sleep(1)

    # Generate ASCII solution from .pzl
    dictionary = {}
    parse_pzl("tmp0000.pzl", dictionary)
    
    solution = draw_bw_solution(dictionary)
    #print("[5] Send solution:\n{}\n".format(solution))
    print("[5] Send solution")

    io.sendline(solution)


#############################
###### SOLVING LEVEL 2 ######
#############################
def add_colors(pzl, num_colors, colors):
    #print("Adding colors..")
    pzl.append("{}\n".format(num_colors))
    for i in range(len(colors)):
        pzl.append("{}\n".format(colors[i]))
        hexcolor = colors[i]
        colors[i] = "{} {} {}".format(int(hexcolor[1:3], 16), 
                int(hexcolor[3:5], 16), int(hexcolor[5:7], 16))
        #print(colors[i])
    pzl.append("\n")


def read_vertical_lvl2(vert_pzl, puzzle, colors):
    print("[0] Reading vertical numbers...")

    lines = []
    cnt = 0
    start_cnt = 0

    second_line = puzzle[1]
    for char in second_line:
        if char is "|":
            break
        start_cnt += 1

    for line in puzzle:
        #print("line: {}".format(line))
        cnt += 1
        if "--------" in line:
            break

        line = line[start_cnt:]
        line = line.replace("|", "")
        line = line.replace("     ", " 0 ")
        line = line.split()
        #print("line: {}".format(line))
        lines.append(line)

    m = np.array(lines)
    rotated = np.rot90(m, 3)
    rotated = np.flip(rotated, 1)

    for i in range(len(rotated)):
        if all(v == "|" for v in rotated[i]):
            rotated = rotated[i:]
            break

    #print("rotated: num lines {}, len {}\n{}".format(len(rotated), len(rotated[1]), rotated))

    #print("Colors: {}".format(colors))
    for line in rotated:
        #print("line: {}".format(line))
        elems = []
        if all(v == "0" for v in line):
            vert_pzl.append("0\n")
        else: 
            num_elems = 0
            for char in line:
                if char != '0':
                    char = char.split("(")
                    #print("charrrrr: {}, {}".format(char[0], char[1]))
                    num = char[0]
                    color = char[1].strip('|').strip(")")
                    hexcolor = colors[int(color)]
                    num_elems += 1
                    elems.append("{} {} ".format(num, hexcolor))
            vert_pzl.append("{} {} \n".format(num_elems, ''.join(elems).rstrip())) #.encode("utf-8")))

    return cnt


def read_horizontal_lvl2(pzl, puzzle, colors):
    print("[1] Reading horisontal numbers...")

    for line in puzzle:
        if "--------" in line:
            break

        line = line.split()
        num_elems = 0
        elems = []
        #print("line: {}".format(line))

        for char in line:
            if char is '|':
                break
            
            char = char.split("(")
            #print("charrrrr: {}".format(char))
            num = char[0]
            color = char[1].strip('|').strip(")")
            hexcolor = colors[int(color)]
            num_elems += 1
            elems.append("{} {} ".format(num, hexcolor))

        pzl.append("{} {} \n".format(num_elems, ''.join(elems).rstrip())) #.encode("utf-8"))


def solve_puzzle_level2(num_colors, color_dict, grid, puzzle):
    # Port to .pzl
    pzl = []

    add_colors(pzl, num_colors, color_dict)
    pzl.append("{}\n".format(grid))
    pzl.append("\n")
    
    cnt = 1 
    vertical_pzl = []
    lines = read_vertical_lvl2(vertical_pzl, puzzle[cnt:], color_dict)
    cnt += lines
    read_horizontal_lvl2(pzl, puzzle[cnt:], color_dict)
    pzl.append("\n")
    pzl.append(''.join(vertical_pzl))
    pzl.append("\n")

    write_to_file(pzl)
    #print("Puzzle ({}):\n{}".format(grid, pzl))

    # Solve nonogram with solver
    os.system("./Nonograms/build/nonograms_solver -i tmp.pzl -o tmp") 
    time.sleep(1)

    # use solver to generate .pzl of image
    os.system("./Nonograms/build/nonograms_solver -p tmp0000.png")
    time.sleep(1)

    # Generate ASCII solution from .pzl
    dictionary = {}
    parse_pzl("tmp0000.pzl", dictionary)

    solution = draw_color_solution(dictionary)
    #print("[5] Send solution:\n{}\n".format(solution))
    print("[5] Send solution")

    io.sendline(solution)


def recv_bw_puzzle():
    # Receive puzzle
    grid = io.recvline().decode("utf-8").rstrip()
    io.recvuntil("Puzzle:\n")
    puzzle = io.recvuntil("Only send me the grid. It needs the same borders.").decode("utf-8")
    puzzle = puzzle.split("\n")
    
    #print("Puzzle ({}):".format(grid))
    #for line in puzzle:
    #    print(line)

    puzzle = puzzle[:-2]
    
    # Receive the rest of the output before sending back
    io.recvuntil("End with new line containing 'EOF'\n")

    return grid, puzzle


def recv_color_puzzle():
    # Receive puzzle
    start = io.recvuntil("---START---\n").decode("utf-8")
    print("Start:\n{}".format(start))

    # Read colors
    num_colors = int(io.recvline().decode("utf-8").rstrip())
    colors = io.recvlines(num_colors) #.decode("utf-8").split()
    color_dict = {}
    #print("received colors: {}".format(colors))
    for color in colors:
        color = color.decode("utf-8")
        color = color.split("=")
        #print("color: {}".format(color))
        color_dict[int(color[0])] = color[1]

    grid = io.recvline().decode("utf-8").rstrip()
    #print("Grid: {}".format(grid))
    io.recvuntil("Puzzle:\n")
    puzzle = io.recvuntil("Only send me the grid. It needs the same borders.").decode("utf-8")
    puzzle = puzzle.split("\n")
    
    #print("Puzzle ({}):\nColors({}):\n{}".format(grid, num_colors, color_dict))
    for line in puzzle:
        print(line)

    puzzle = puzzle[:-2]
    
    # Receive the rest of the output before sending back
    io.recvuntil("End with new line containing 'EOF'\n")

    return num_colors, color_dict, grid, puzzle


def recv_end():
    res = io.recvline().decode("utf-8")
    print("End 1: {}".format(res))
    if "Yatta" not in res:
        raise Exception("No yatta :'(")

    res = io.recvline().decode("utf-8")
    print("End 2: {}".format(res))
    if "NANI?!" in res:
        return False

    return True


def main():
    try:
        start = io.recvuntil("---START---\n").decode("utf-8")
        print("Start:\n{}".format(start))
        cnt = 0
        while(True):
            print("------------------ ROUND {} ------------------".format(cnt))
            grid, puzzle = recv_bw_puzzle()
            solve_puzzle_level1(grid, puzzle)
            if not recv_end():
                print("LEVEL 1 SOLVED!")
                break
            cnt += 1

        # level 2
        #io.interactive()
        #start = io.recvuntil("---START---\n").decode("utf-8")
        #print("Start:\n{}".format(start))
        cnt = 0
        while(True):
            print("------------------ ROUND {} ------------------".format(cnt))
            num_colors, color_dict, grid, puzzle = recv_color_puzzle()
            solve_puzzle_level2(num_colors, color_dict, grid, puzzle)
            recv_end()
            cnt += 1

    except Exception as e:
        print(e)
        io.interactive()
    

if __name__ == "__main__":
    main()

