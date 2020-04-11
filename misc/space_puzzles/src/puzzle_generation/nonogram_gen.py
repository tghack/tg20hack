import argparse


#############################################
###### PARSE PZL FROM izarion/Nonogram ######
#############################################
def parse_pzl(filename, dictionary):
    print("Parsing .pzl file...")
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
    

#################################################
###### REMOVE WHITE ELEMENTS AND RGB ELEMS ######
#################################################
def clear_dict_axis_bw(dictionary, axis):
    # remove all white elements and color codes from grid
    elems = [line[0] for line in dictionary["{}".format(axis)]]
    max_elem = int(max(elems))
    #print("Elems: \n{}, max {}".format(elem, max_elem))

    cnt = 0
    idx = 0
    while True:
        line = dictionary["{}".format(axis)][idx].rstrip().split()
        #print("Horizontal: idx {}, cnt {}, len {}\n{}".format(idx, cnt, len(line), line))
        list_seq = line[-4:] if cnt == 0 else line[-4-cnt:-cnt]
        #print("Sequence: idx {}, cnt {},\n{}".format(idx,cnt,list_seq))
        if list_seq[1:] == ['255', '255', '255']: 
            if cnt == 0:
                del line[-4:] 
            else:
                del line[-4-cnt:-cnt]
            line[0] = str(int(line[0]) - 1)
        else:
            if cnt == 0:
                del line[-3:]
            else:
                del line[-3-cnt:-cnt]
            cnt += 1

        dictionary["{}".format(axis)][idx] = ' '.join(line)
        #print("Line: idx {}, cnt {}, len {}\n{}".format(idx, cnt, len(line), 
        #    dictionary["{}".format(axis)][idx]))

        if len(line) == cnt + 1:
            idx += 1
            cnt = 0

        if idx >= len(dictionary["{}".format(axis)]):
            break


def clear_dict_bw(dictionary):
    print("Clearing black/white puzzle for white and RGB elements...")
    clear_dict_axis_bw(dictionary, "horizontal")
    clear_dict_axis_bw(dictionary, "vertical")

    #print("Horizontal: \n{}".format(dictionary["horizontal"]))
    #print("Vertical: \n{}".format(dictionary["vertical"]))
    #print("-------------------------------------")


##############################################
###### DRAW BLACK/WHITE NONOGRAM PUZZLE ######
##############################################
def draw_bw_puzzle(dictionary):
    print("Drawing black/white puzzle...")
    clear_dict_bw(dictionary)
    # make list of number of elements in each row/column
    hor_elems = [int(line.split()[0]) for line in dictionary["horizontal"]] 
    ver_elems = [int(line.split()[0]) for line in dictionary["vertical"]]
    # maximum number of elements in row/column
    max_h = max(hor_elems)
    max_v = max(ver_elems)
    # number of lines
    lines_h = len(dictionary["horizontal"])
    lines_v = len(dictionary["vertical"])
    #print("Horizontal elems: \n{}, max {}".format(hor_elems, max_h))
    #print("Vertical elems: \n{}, max {}".format(ver_elems, max_v))

    # make empty matrix
    h = [[" " for x in range(lines_h)] for y in range(max_h)]

    # fill matrix for vertical elements
    for i in range(max_h):
        for j in range(lines_h):
            line = dictionary["horizontal"][j].split()
            if int(line[0]) > i:
                # Read last elem first
                h[max_h - i - 1][j] = line[len(line) - i - 1] 
    
    puzzle = []

    add_split_line(puzzle, lines_h * 2, max_v * 2)

    for elem in h:
        # Remove space from join to get compact mode
        line = "{:>{max_v}}|{}|".format(" ", " ".join(elem), max_v=max_v*2)
        puzzle.append(line)
        print(line)

    add_split_line(puzzle, lines_h * 2, max_v * 2)

    for line in dictionary["vertical"]:
        line = "{:>{max_v}}|{:>{lines_h}}|".format(line[2:], " ", max_v=max_v*2, 
                lines_h=(lines_h * 2) - 1)
        puzzle.append(line)
        print(line)

    add_split_line(puzzle, lines_h * 2, max_v * 2)

    return puzzle


def add_split_line(puzzle, lines_h, max_v):
    split_line = "{}".format("-" * (max_v + lines_h + 1))
    puzzle.append(split_line)
    print(split_line)


################################################
###### DRAW BLACK/WHITE NONOGRAM SOLUTION ######
################################################
def draw_bw_solution(dictionary):
    print("Drawing black/white solution..")
    
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

    return solution
    

###################################
###### REMOVE WHITE ELEMENTS ######
###################################
def clear_dict_axis_color(d, axis):
    elems = [line[0] for line in d["{}".format(axis)]]
    max_elem = int(max(elems))
    #print("Elems: \n{}, max {}".format(elem, max_elem))

    color_dict = d["color_ids"]
    print("Color dictionary:\n{}".format(color_dict))

    cnt = 0
    idx = 0
    while True:
        line = d["{}".format(axis)][idx].rstrip().split()
        seq = line[-4:] if cnt == 0 else line[-4-cnt:-cnt]
        if seq[1:] == ['255', '255', '255']: 
            if cnt == 0:
                del line[-4:] 
            else:
                del line[-4-cnt:-cnt]
            line[0] = str(int(line[0]) - 1)
        elif seq == ['0']:
            line[0] = "0"
        else:
            #print("Sequence: {}".format(seq))
            hexcolor = "#{:02x}{:02x}{:02x}".format(int(seq[1]),int(seq[2]),int(seq[3]))
            #print("Hexcolor: {}".format(hexcolor))
            color_id = color_dict[hexcolor]
            if cnt == 0:
                line[-4] = "{}({})".format(line[-4], color_id)
                del line[-3:]
            else:
                line[-4-cnt] = "{}({})".format(line[-4-cnt], color_id)
                del line[-3-cnt:-cnt]
            cnt += 1

        d["{}".format(axis)][idx] = ' '.join(line)

        if len(line) == cnt + 1:
            idx += 1
            cnt = 0

        if idx >= len(d["{}".format(axis)]):
            break


def clear_dict_color(dictionary):
    print("Clearing colored puzzle of white elements...")
    clear_dict_axis_color(dictionary, "horizontal")
    clear_dict_axis_color(dictionary, "vertical")


########################################
###### DRAW COLOR NONOGRAM PUZZLE ######
########################################
def draw_color_puzzle(dictionary):
    print("Drawing colored puzzle...")
    clear_dict_color(dictionary)

    # make list of number of elements in each row/column
    hor_elems = [int(line.split()[0]) for line in dictionary["horizontal"]] 
    ver_elems = [int(line.split()[0]) for line in dictionary["vertical"]]
    # maximum number of elements in row/column
    max_h = max(hor_elems)#hor_elems.sort()[-1]#int(max(hor_elems)) 
    max_v = max(ver_elems)#ver_elems.sort()[-1]#int(max(ver_elems))
    # number of rows, or width of row/column
    lines_h = len(dictionary["horizontal"]) 
    lines_v = len(dictionary["vertical"]) 
    print("Horizontal elems: \n{}, max {}".format(hor_elems, max_h))
    print("Vertical elems: \n{}, max {}".format(ver_elems, max_v))

    # make initial empty matrix for vertical elements
    h = [["    " for x in range(lines_h)] for y in range(max_h)]

    # fill matrix for vertical elements
    print("max_h: {}, max_v: {}".format(max_h, max_v))
    for i in range(max_h):
        for j in range(lines_h):
            line = dictionary["horizontal"][j].split()
            if int(line[0]) > i:
                # Read last elem first
                h[max_h - i - 1][j] = line[len(line) - i - 1] 
    
    puzzle = []

    add_split_line(puzzle, lines_h * 2, max_v * 5)

    for elem in h:
        # This is not really horisontal in the sense of nonograms, SORRY FOR 
        # THE CONFUSION DONT HAVE TIME TO FIX. This is the top part of the puzzle, 
        # hence the part where you are solving downwards/vertically. 
        # Remove space from join to get compact mode
        line = "{:>{max_v}}|{}|".format(" ", " ".join(elem), max_v=max_v * 5)
        puzzle.append(line)
        print(line)

    add_split_line(puzzle, lines_h * 2, max_v * 5)

    for line in dictionary["vertical"]:
        # Not really vertical... See comment above...
        line = "{:>{max_v}}|{:>{lines_h}}|".format(line[2:], " ", 
                max_v=max_v * 5, 
                lines_h=(lines_h * 2) - 1)
        puzzle.append(line)
        print(line)

    add_split_line(puzzle, lines_h * 2, max_v * 5)

    return puzzle


##########################################
###### DRAW COLOR NONOGRAM SOLUTION ######
##########################################
def draw_color_solution(d):
    print("Drawing colored solution..")
    
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
    print("Solution:\n{}".format(solution))
    
    return solution


###########################
###### WRITE TO FILE ######
###########################
def write_to_file(d, pzl, sol, color):
    print("Writing to file...")
    
    #dictionary["num_colors"] = num_colors
    #dictionary["grid"] = grid
    #dictionary["h_len"] = horizontal_len
    #dictionary["v_len"] = vertical_len
    #dictionary["horizontal"] = horizontal
    #dictionary["vertical"] = vertical

    filename = "./puzzles-bw.txt"
    if color:
        filename = "./puzzles-color.txt"
        
    with open(filename, 'a') as f:
        # Puzzle 
        f.write("---START---\n")
        if color: 
            color_dict = d["color_ids"]
            f.write("{}\n".format(d["num_colors"]))
            for color, cid in enumerate(color_dict):
                f.write("{}={}\n".format(color, cid))

        f.write("{}\n".format(d["grid"]))
        
        f.write("Puzzle:\n")
        for line in pzl:
            f.write("{}\n".format(line))

        # Solution
        f.write("Solution:\n")
        for line in sol:
            f.write("{}".format(line))

        f.write("---END---\n")


def generate_nonogram(filename, color):
    nonogram_dict = {}
    parse_pzl(filename, nonogram_dict)

    if color:
        solution = draw_color_solution(nonogram_dict)
        puzzle = draw_color_puzzle(nonogram_dict)
    else:
        solution = draw_bw_solution(nonogram_dict)
        puzzle = draw_bw_puzzle(nonogram_dict)

    write_to_file(nonogram_dict, puzzle, solution, color)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='Parse a .pzl file to a nonogram puzzle')
    parser.add_argument('filename', metavar='F', type=str, nargs='?',
        help='filename of file to parse')
    parser.add_argument('--color', metavar='c', type=bool, nargs='?',
        default=False, help='Colors (True) or black/white (False)')

    args = parser.parse_args()

    generate_nonogram(args.filename, args.color)
    print("job's done!")

