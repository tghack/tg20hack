from pwn import *

debug = False 
if debug == True:
    r = process("./re_noob2")
    # uncomment if using ssh
    #context(terminal = ["tmux", "splitw"])
    #gdb.attach(r, """
    #    c
    #    """)
else:
    r = remote("localhost", 5000)

r.recvline()
r.sendline("Captain bolbz")

r.recvline()
r.sendline("4200000000^42")

r.recvuntil("What year is this?\n")
r.sendline("2820")

r.recvline()
r.sendline("133700")

r.interactive()
