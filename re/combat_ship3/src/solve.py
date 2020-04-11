from pwn import *

debug = False 
if debug == True:
    r = process("./re_noob3")
    # uncomment if using ssh
    #context(terminal = ["tmux", "splitw"])
    #gdb.attach(r, """
    #    c
    #    """)
else:
    r = remote("localhost", 5001)

r.recvline()
r.sendline("Captain noco")

r.recvline()
r.sendline("3205076259^42")

r.recvuntil("What year is this?\n")
r.sendline("4113")

r.recvline()
r.sendline("701710")

r.interactive()
