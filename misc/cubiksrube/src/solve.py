#!/usr/bin/env python3
import sys
from pwn import *
from rubik import Cube


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

def rev(moves):
    return ' '.join([i.strip("'") + " '"[len(i):] for i in moves.split()[::-1]])

def rev(moves):
    result = []
    for i in moves.split()[::-1]:
        result.append(i.strip("'") + " '"[len(i):])
    return ' '.join(result)


def run_solver():
    host = "cubiks.tghack.no"
    port = 7001
    
    if len(sys.argv) == 3:
        host = sys.argv[1]
        port = sys.argv[2]

    r = remote(host, port)
    r.recvuntil("right?\n\n")
    scrambled = r.recvuntil("\n\n").decode()
    r.recvuntil("might help you.\n")
    moves = r.recvline().decode()
    
    r.close()

    log.info(scrambled)

    scrambled = scrambled.replace("\n", "").replace(' ', '')
    log.info("Scrambled flag: " + scrambled)
    log.info("")

    rev_moves = rev(moves)
    log.info("Reversed moves: " + rev_moves)

    cube = Cube(scrambled)
    cube.do_moves(rev_moves)
    log.info("Reversed cube:")
    log.info(cube)
    log.info("")

    flag = cube.flat_str()
    assert flag == open("../flag.txt", "r").read().rstrip()

    log.success("Flag: " + flag)

# Test if task works. Exit codes are for our automated task checker.
try:
    run_solver()
except (OSError, AssertionError, NameError, EOFError) as e:
    log.warning("Problem solving task! {}".format(e))
    exit(102)
else:
    exit(101)
