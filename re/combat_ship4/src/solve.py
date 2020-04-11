from pwn import *

debug = False 
if debug == True:
    r = process("./re_noob4")
    # uncomment if using ssh
    #context(terminal = ["tmux", "splitw"])
    #gdb.attach(r, """
    #    c
    #    """)
else:
    r = remote("localhost", 5002)

password = "{} {}".format("42", "1337")

r.recvline() # Combat Ship software starting...
r.recvline() # Blank line

r.recvline() # Please enter password:
r.sendline(password)

r.interactive()
