# A much cleaner solve script made by sampriti
from pwn import *
import string
import regex as re
import subprocess

proc = remote("puzzle.tghack.no", 7002)

print proc.recvline().strip()

# LEVEL 1
for ctr in range(43):
    proc.recvline()
    line = proc.recvline()[:-1]
    print line
    rows, cols = map(int, line.strip().split())

    proc.recvlines(3)

    col_hints = []
    while True:
        line = proc.recvline()[:-1]
        #print line
        if line[0] == "-":
            break
        line = line.split("|")[1]
        pattern = "^" + " ".join(["([0-9 ]+?)"]*cols) + "$"
        hints = [re.search(pattern, line).group(i+1) for i in range(cols)]
        hints = ['.' if x == " " else x for x in hints]
        col_hints.append(hints)

    column_values = []
    for i in range(cols):
        start = False
        curr = []
        for j in range(len(col_hints)):
            if col_hints[j][i] != ".":
                start = True
                curr.append(int(col_hints[j][i]))
            else:
                assert not start
        column_values.append(curr)

    row_values = []
    for i in range(rows):
        line = proc.recvline()[:-1]
        #print line
        line = line.strip().split("|")[0]
        curr = map(int, line.strip().split())
        row_values.append(curr)
    print proc.recvline()[:-1]

    f = open("input.mk", "wb")
    f.write("{} {}\n".format(rows, cols))
    for i in range(rows):
        f.write(" ".join(map(str, row_values[i])) + "\n")
    f.write("#\n")
    for i in range(cols):
        f.write(" ".join(map(str, column_values[i])) + "\n")
    f.close()

    proc.recvlines(3)
    output = None
    try:
        output = subprocess.check_output("./pbnsolve-1.10/pbnsolve -aHECGPM -fmk input.mk", shell=True)
    except subprocess.CalledProcessError:
        output = subprocess.check_output("./pbnsolve-1.10/pbnsolve -aLHECGPM -fmk input.mk", shell=True)
    print output

    ans = output.strip().split("\n")
    if ":" in ans[0]:
        ans = ans[1:]

    print "\n\n"

    send_ans = []
    send_ans.append("-" * (2*cols+1))
    for i in range(rows):
        curr = list(ans[i].replace(".", " "))
        send_ans.append("|" + " ".join(curr) + "|")
    send_ans.append("-" * (2*cols+1))
    send_ans.append("EOF")

    fin = "\n".join(send_ans)
    #print fin
    proc.sendline(fin)

    print proc.recvline()

charset = string.printable[:62]

proc.recvline()
print proc.recvline()
proc.recvuntil("EOF\n")

# LEVEL 2
for ctr in range(56):
    proc.recvline()
    colors = []
    line = proc.recvline()[:-1]
    print line
    num_colors = int(line.strip())
    print num_colors
    color_names = []
    for i in range(num_colors):
        line = proc.recvline().strip()
        print line
        name, color = line.split("=")
        color_names.append(name)
        colors.append([i, name, color[1:]])

    line = proc.recvline()[:-1]
    print line
    rows, cols = map(int, line.strip().split())
    proc.recvlines(3)

    col_hints = []
    while True:
        line = proc.recvline()[:-1]
        #print line
        if line[0] == "-":
            break
        line = line.split("|")[1]
        pattern = "^" + " ".join(["((?:[0-9()]|    )+?)"]*cols) + "$"
        hints = [re.search(pattern, line).group(i+1) for i in range(cols)]
        hints = ['.' if x == "    " else x for x in hints]
        col_hints.append(hints)

    column_values = []
    for i in range(cols):
        start = False
        curr = []
        for j in range(len(col_hints)):
            if col_hints[j][i] != ".":
                start = True
                curr.append(col_hints[j][i])
            else:
                assert not start
        column_values.append(curr)

    row_values = []
    for i in range(rows):
        line = proc.recvline()[:-1]
        #print line
        line = line.strip().split("|")[0]
        curr = line.strip().split()
        row_values.append(curr)
    print proc.recvline()[:-1]

    proc.recvlines(3)
    f = open("input.xml", "wb")
    f.write("""<?xml version="1.0"?>
    <!DOCTYPE pbn SYSTEM "pbn-0.3.dtd">

    <puzzleset>

    <puzzle type="grid" defaultcolor="black">
    """)

    for i, name, color in colors:
        f.write('<color name="{}" char="{}">{}</color>\n'.format(name, charset[i], color))

    f.write('<clues type="columns">\n')
    for i in range(cols):
        f.write("<line>")
        for val in column_values[i]:
            count = int(val.split("(")[0])
            name = val.split("(")[1][:-1]
            assert name in color_names
            f.write('<count color="{}">{}</count>'.format(name, count))
        f.write("</line>\n")
    f.write("</clues>\n")

    f.write('<clues type="rows">\n')
    for i in range(rows):
        f.write("<line>")
        for val in row_values[i]:
            count = int(val.split("(")[0])
            name = val.split("(")[1][:-1]
            assert name in color_names
            f.write('<count color="{}">{}</count>'.format(name, count))
        f.write("</line>\n")
    f.write("</clues>\n")

    f.write("</puzzle>\n")
    f.write("</puzzleset>\n")
    f.close()

    output = None
    try:
        output = subprocess.check_output("./pbnsolve-1.10/pbnsolve -aHECGPM -fxml input.xml", shell=True)
    except subprocess.CalledProcessError:
        output = subprocess.check_output("./pbnsolve-1.10/pbnsolve -aLHECGPM -fxml input.xml", shell=True)
    output = output.replace("\x00", ".")
    print output

    ans = output.strip().split("\n")
    if ":" in ans[0]:
        ans = ans[1:]

    print "\n\n"

    send_ans = []
    send_ans.append("-" * (2*cols+1))
    for i in range(rows):
        curr = [colors[charset.index(x)][1] if x != "." else " " for x in ans[i]]
        send_ans.append("|" + " ".join(curr) + "|")
    send_ans.append("-" * (2*cols+1))
    send_ans.append("EOF")

    fin = "\n".join(send_ans)
    #print fin
    proc.sendline(fin)

    print proc.recvline()[:-1]
    print proc.recvline()[:-1]

proc.interactive()

# TG20{THANK YOU FOR WASTING SOME TIME PUZZLING SOLVES}
